fn main() {
    let bpf_linker = which::which("bpf-linker").expect("bpf-linker is not on PATH");
    println!("cargo:rerun-if-changed={}", bpf_linker.display());
}
