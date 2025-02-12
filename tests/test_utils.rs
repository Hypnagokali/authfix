pub const TEST_OUT: &str = "test-out";

pub fn test_out_path(path: &str) -> String {
    format!("{TEST_OUT}/{path}")
}
