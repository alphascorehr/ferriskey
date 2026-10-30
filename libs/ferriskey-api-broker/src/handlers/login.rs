use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::LOCATION},
    response::IntoResponse,
};
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use ferriskey_core::domain::abyss::identity_provider::broker::{BrokerLoginInput, BrokerService};

use ferriskey_api_core::url::FullUrl;
use ferriskey_api_core::{
    api_entities::api_error::{ApiError, ApiErrorResponse},
    app_state::AppState,
};

use super::super::validators::BrokerLoginRequest;

/// Set by `/authorize` on the auth session the login page belongs to.
const AUTH_SESSION_COOKIE: &str = "FERRISKEY_SESSION";

/// The auth session this broker login completes.
///
/// An explicit `session_id` wins. Otherwise the login page's own session, from
/// the cookie `/authorize` set, unless the request brings its own PKCE challenge:
/// that is a flow started on the login page itself (the console's), whose
/// verifier could never satisfy the session's original challenge.
fn linked_auth_session(params: &BrokerLoginRequest, headers: &HeaderMap) -> Option<Uuid> {
    if params.session_id.is_some() || params.code_challenge.is_some() {
        return params.session_id;
    }

    CookieJar::from_headers(headers)
        .get(AUTH_SESSION_COOKIE)
        .and_then(|cookie| Uuid::parse_str(cookie.value()).ok())
}

/// Initiates SSO login via an external identity provider
///
/// This endpoint validates the request, looks up the identity provider,
/// creates a broker session, and redirects the user to the IdP's authorization URL.
#[utoipa::path(
    get,
    path = "/broker/{alias}/login",
    tag = "broker",
    summary = "Initiate SSO login via identity provider",
    description = "Redirects the user to the external identity provider for authentication",
    params(
        ("realm_name" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "Identity provider alias"),
        BrokerLoginRequest
    ),
    responses(
        (status = 302, description = "Redirect to identity provider authorization URL"),
        (status = 400, description = "Bad request - invalid parameters", body = ApiErrorResponse),
        (status = 404, description = "Identity provider not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    )
)]
pub async fn broker_login(
    Path((realm_name, alias)): Path<(String, String)>,
    State(state): State<AppState>,
    FullUrl(_, base_url): FullUrl,
    headers: HeaderMap,
    Query(params): Query<BrokerLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_session_id = linked_auth_session(&params, &headers);
    let base_url = format!("{base_url}{}", state.args.server.root_path);
    let result = state
        .service
        .initiate_login(BrokerLoginInput {
            realm_name,
            alias,
            client_id: params.client_id,
            redirect_uri: params.redirect_uri,
            response_type: params.response_type,
            scope: params.scope,
            state: params.state,
            nonce: params.nonce,
            auth_session_id,
            code_challenge: params.code_challenge,
            code_challenge_method: params.code_challenge_method,
            base_url,
        })
        .await?;

    Ok((StatusCode::FOUND, [(LOCATION, result.authorization_url)]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    fn request(session_id: Option<Uuid>, code_challenge: Option<&str>) -> BrokerLoginRequest {
        BrokerLoginRequest {
            client_id: "app".to_string(),
            redirect_uri: "https://app.example/callback".to_string(),
            response_type: "code".to_string(),
            scope: None,
            state: Some("app-state".to_string()),
            nonce: None,
            session_id,
            code_challenge: code_challenge.map(str::to_string),
            code_challenge_method: code_challenge.map(|_| "S256".to_string()),
        }
    }

    fn with_session_cookie(session: Uuid) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{AUTH_SESSION_COOKIE}={session}")
                .parse()
                .expect("cookie header"),
        );
        headers
    }

    #[test]
    fn an_application_login_page_links_the_session_from_the_cookie() {
        let session = Uuid::new_v4();

        let linked = linked_auth_session(&request(None, None), &with_session_cookie(session));

        assert_eq!(linked, Some(session));
    }

    #[test]
    fn an_explicit_session_id_wins_over_the_cookie() {
        let explicit = Uuid::new_v4();

        let linked = linked_auth_session(
            &request(Some(explicit), None),
            &with_session_cookie(Uuid::new_v4()),
        );

        assert_eq!(linked, Some(explicit));
    }

    #[test]
    fn a_request_with_its_own_challenge_is_not_linked_to_the_cookie_session() {
        let linked = linked_auth_session(
            &request(None, Some("challenge")),
            &with_session_cookie(Uuid::new_v4()),
        );

        assert_eq!(linked, None);
    }

    #[test]
    fn no_cookie_and_no_session_id_links_nothing() {
        assert_eq!(
            linked_auth_session(&request(None, None), &HeaderMap::new()),
            None
        );
    }
}
