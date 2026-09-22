//! Build-time binding generator, never an application dependency.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let input = args.next().ok_or("Wasm input required")?;
    let output = args.next().ok_or("Output directory required")?;
    if args.next().is_some() { return Err("Unexpected argument".into()); }
    wasm_bindgen_cli_support::Bindgen::new()
        .input_path(std::path::PathBuf::from(input)).web(true)?
        .out_name("cvld_holder").typescript(true)
        .generate(std::path::PathBuf::from(output))?;
    Ok(())
}
