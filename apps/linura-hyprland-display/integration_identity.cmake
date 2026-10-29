function(linura_display_integration_identity source_dir output_dir)
    # Shared by compositor and protected owner builds. No build path, clock,
    # environment variable or compiler-generated file enters this source ID.
    set(inputs
        CMakeLists.txt
        compositor_display_service.cpp compositor_display_service.h
        display_transaction.cpp display_transaction.h
        integration_identity.cmake source_integration.py
        pinned_backend.cpp pinned_integration.h rule_overlay.h native_scale.h
        native_power_inhibitor.cpp native_power_inhibitor.h
        native_inhibitor_fd.h
        native_owner_admission.cpp native_owner_admission.h owner_identity.cpp
        native_output_identity.h recovery_witness.h
        wire_endpoint.cpp wire_endpoint.h
        protocols/linura-display-management-v1.xml
    )
    set(material "linura.hyprland-display.source.v1\n")
    foreach(input IN LISTS inputs)
        if(NOT EXISTS "${source_dir}/${input}" OR IS_SYMLINK "${source_dir}/${input}")
            message(FATAL_ERROR "Missing or substituted pinned native integration source: ${input}")
        endif()
        file(SHA256 "${source_dir}/${input}" input_digest)
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source_dir}/${input}")
        string(APPEND material "${input}\n${input_digest}\n")
    endforeach()
    string(SHA256 LINURA_DISPLAY_INTEGRATION_DIGEST "${material}")
    file(MAKE_DIRECTORY "${output_dir}")
    file(WRITE "${output_dir}/linura-display-integration-build.h"
        "#pragma once\n\nnamespace Linura::HyprlandDisplay {\n"
        "inline constexpr char IntegrationSourceDigest[] = \"${LINURA_DISPLAY_INTEGRATION_DIGEST}\";\n}\n")
endfunction()
