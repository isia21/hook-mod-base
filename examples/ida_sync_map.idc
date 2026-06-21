#include <idc.idc>

// Применяет изменения из DLL (Хуки, NOP-кейвы, VTable)
static apply_sync(addr, size, name, is_nop, h_type) {
    auto i, color, current_cmt, prefix;
    if (h_type == 2) { // HookType::VTable
        color = 0xFFFF00; // Cyan
        prefix = "[VTABLE_DLL] ";
        //patch_byte(addr + 0, 0); patch_byte(addr + 1, 0);
        //patch_byte(addr + 2, 0); patch_byte(addr + 3, 0);
    } else {
        color = is_nop ? 0x00FF00 : 0xFF00FF; // Lime / Magenta
        prefix = is_nop ? "[NOP_CAVE] " : "[REVERSE] ";
        if (is_nop) {
            for (i = 0; i < size; i++) patch_byte(addr + i, 0x90);
        }
    }
    for (i = 0; i < size; i++) set_color(addr + i, CIC_ITEM, color);
    current_cmt = get_cmt(addr, 0);
    if (current_cmt == 0 || current_cmt == "") {
        set_cmt(addr, prefix + name, 0);
    } else if (strstr(current_cmt, name) == -1) {
        set_cmt(addr, current_cmt + " | " + prefix + name, 0);
    }
}

static find_orphans() {
    auto addr, start, end, size, name, dref;
    auto h_count, h_size, v_count, v_size;
    h_count = 0; h_size = 0; v_count = 0; v_size = 0;

    msg("\n--- Running Orphan Discovery --- (Hard vs Virtual)\n");
    for (addr = NextFunction(0); addr != BADADDR; addr = NextFunction(addr)) {
        if (get_func_attr(addr, FUNCATTR_FLAGS) & FUNC_LIB) continue;
        if (get_first_cref_to(addr) == BADADDR) {
            start = get_func_attr(addr, FUNCATTR_START);
            end = get_func_attr(addr, FUNCATTR_END);
            size = end - start;
            name = get_func_name(addr);
            dref = get_first_dref_to(addr);
            if (dref == BADADDR) {
                msg("  [HARD]   0x%08X | %d bytes | %s\n", addr, size, name);
                h_count = h_count + 1;
                h_size = h_size + size;
            } else {
                msg("  [VIRTUAL] 0x%08X | %d bytes | %s (DRef: 0x%08X)\n", addr, size, name, dref);
                v_count = v_count + 1;
                v_size = v_size + size;
            }
        }
    }
    msg("\n--- ORPHAN SUMMARY ---\n");
    msg("  HARD ORPHANS:    %d funcs, %d bytes (%.2f KB)\n", h_count, h_size, h_size/1024.0);
    msg("  VIRTUAL ORPHANS: %d funcs, %d bytes (%.2f KB)\n", v_count, v_size, v_size/1024.0);
    msg("  TOTAL RECLAIM:   %d bytes (%.2f KB)\n", h_size + v_size, (h_size + v_size)/1024.0);
}
static main() {
    msg("\n=================== XXXXXReverse Sync Engine ===================\n");
    apply_sync(0x401140, 5, "GameEngine::UpdateInput", 0, 1);
    apply_sync(0x401160, 5, "GameEngine::PlayAmbientSound", 0, 1);
    apply_sync(0x403338, 4, "IRenderSystem::RenderFrame (VTable)", 0, 2);
    apply_sync(0x40130d, 5, "Main -> RunNetworkLoop (Call Site)", 0, 0);

    msg("--- Sync complete. Reanalyzing... ---\n");
    find_orphans();
    msg("================================================================\n");
}
