
#[macro_export]
macro_rules! lazy_regex {
    ($name:ident = $re:literal $(,)?) => {
        static $name: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| {
                regex::Regex::new($re)
                    .expect(concat!("Invalid regex: ", $re))
            });
    };

    (pub $name:ident = $re:literal $(,)?) => {
        pub static $name: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| {
                regex::Regex::new($re)
                    .expect(concat!("Invalid regex: ", $re))
            });
    };
}