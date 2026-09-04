{
  "targets": [
    {
      "target_name": "memloader",
      "sources": [
        "pe-loader/addon.cc",
        "pe-loader/Main.cc",
        "pe-loader/Hooks.cc",
        "pe-loader/Reflective.cc",
        "Common/Encrypt.cc",
        "Common/Hash.cc",
        "Common/ObfLoadLibraryA.cc",
        "Common/Syscalls.cc",
        "Common/Win32.cc"
      ],
      "include_dirs": [
        "pe-loader",
        "Common"
      ],
      "defines": [
        "NODE_ADDON_BUILD"
      ],
      "cflags_cc": [
        "-std=c++17"
      ],
      "conditions": [
        [
          "OS==\"win\"",
          {
            "msvs_settings": {
              "VCCLCompilerTool": {
                "AdditionalOptions": [
                  "/std:c++17"
                ]
              }
            }
          }
        ]
      ]
    }
  ]
}
