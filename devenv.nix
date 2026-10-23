{ pkgs, ... }:

{
  packages = [
    pkgs.gcc
    pkgs.pkg-config
    pkgs.glib
    pkgs.jdk21_headless  # REA's Ghidra backend probes `java` on PATH
  ];

  # REA (reverse-engineer-anything) locates its Ghidra backend via this var;
  # it requires a 12.1.x release dir. pkgs.ghidra here is 12.1.2.
  env.GHIDRA_INSTALL_DIR = "${pkgs.ghidra}/lib/ghidra";

  languages.python = {
    enable = true;
    package = pkgs.python3.withPackages (ps: with ps; [
      numpy
      scipy
      pyusb
      cryptography
    ]);
  };

  enterShell = ''
    echo VFS495 Development Environment Loaded
  '';
}
