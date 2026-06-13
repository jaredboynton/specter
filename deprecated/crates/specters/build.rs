fn main() {
    println!(
        "cargo:warning=The specters crate was renamed to warpsock. Update Cargo.toml to depend on warpsock = \"4.2\" and change specter:: imports to warpsock::."
    );
}
