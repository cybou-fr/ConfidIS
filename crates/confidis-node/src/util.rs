pub(crate) fn normalize_endpoint(endpoint: &str) -> String {
    endpoint.trim_end_matches('/').to_string()
}
