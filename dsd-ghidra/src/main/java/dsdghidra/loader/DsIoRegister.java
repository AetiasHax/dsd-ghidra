package dsdghidra.loader;

import org.jetbrains.annotations.NotNull;

public record DsIoRegister(int address, String name) {
    public static final @NotNull DsIoRegister[] ARM9_REGS = {
        new DsIoRegister(0x04000000, "REG_DISPCNT"),
        new DsIoRegister(0x04000004, "REG_DISPSTAT"),
        new DsIoRegister(0x04000006, "REG_VCOUNT"),
        new DsIoRegister(0x04000008, "REG_BG0CNT"),
        new DsIoRegister(0x0400000a, "REG_BG1CNT"),
        new DsIoRegister(0x0400000c, "REG_BG2CNT"),
        new DsIoRegister(0x0400000e, "REG_BG3CNT"),
        new DsIoRegister(0x04000010, "REG_BG0HOFS"),
        new DsIoRegister(0x04000012, "REG_BG0VOFS"),
        new DsIoRegister(0x04000014, "REG_BG1HOFS"),
        new DsIoRegister(0x04000016, "REG_BG1VOFS"),
        new DsIoRegister(0x04000018, "REG_BG2HOFS"),
        new DsIoRegister(0x0400001a, "REG_BG2VOFS"),
        new DsIoRegister(0x0400001c, "REG_BG3HOFS"),
        new DsIoRegister(0x0400001e, "REG_BG3VOFS"),
        new DsIoRegister(0x04000020, "REG_BG2PA"),
        new DsIoRegister(0x04000022, "REG_BG2PB"),
        new DsIoRegister(0x04000024, "REG_BG2PC"),
        new DsIoRegister(0x04000026, "REG_BG2PD"),
        new DsIoRegister(0x04000028, "REG_BG2X"),
        new DsIoRegister(0x0400002c, "REG_BG2Y"),
        new DsIoRegister(0x04000030, "REG_BG3PA"),
        new DsIoRegister(0x04000032, "REG_BG3PB"),
        new DsIoRegister(0x04000034, "REG_BG3PC"),
        new DsIoRegister(0x04000036, "REG_BG3PD"),
        new DsIoRegister(0x04000038, "REG_BG3X"),
        new DsIoRegister(0x0400003c, "REG_BG3Y"),
        new DsIoRegister(0x04000040, "REG_WIN0H"),
        new DsIoRegister(0x04000042, "REG_WIN1H"),
        new DsIoRegister(0x04000044, "REG_WIN0V"),
        new DsIoRegister(0x04000046, "REG_WIN1V"),
        new DsIoRegister(0x04000048, "REG_WININ"),
        new DsIoRegister(0x0400004a, "REG_WINOUT"),
        new DsIoRegister(0x0400004c, "REG_MOSAIC"),
        new DsIoRegister(0x04000050, "REG_BLDCNT"),
        new DsIoRegister(0x04000052, "REG_BLDALPHA"),
        new DsIoRegister(0x04000054, "REG_BLDY"),
        new DsIoRegister(0x04000060, "REG_DISP3DCNT"),
        new DsIoRegister(0x04000064, "REG_DISPCAPCNT"),
        new DsIoRegister(0x04000068, "REG_DISP_MMEM_FIFO"),
        new DsIoRegister(0x0400006c, "REG_MASTER_BRIGHT"),
        new DsIoRegister(0x040000b0, "REG_DMA0SAD"),
        new DsIoRegister(0x040000b4, "REG_DMA0DAD"),
        new DsIoRegister(0x040000b8, "REG_DMA0CNT_L"),
        new DsIoRegister(0x040000ba, "REG_DMA0CNT_H"),
        new DsIoRegister(0x040000bc, "REG_DMA1SAD"),
        new DsIoRegister(0x040000c0, "REG_DMA1DAD"),
        new DsIoRegister(0x040000c4, "REG_DMA1CNT_L"),
        new DsIoRegister(0x040000c6, "REG_DMA1CNT_H"),
        new DsIoRegister(0x040000c8, "REG_DMA2SAD"),
        new DsIoRegister(0x040000cc, "REG_DMA2DAD"),
        new DsIoRegister(0x040000d0, "REG_DMA2CNT_L"),
        new DsIoRegister(0x040000d2, "REG_DMA2CNT_H"),
        new DsIoRegister(0x040000d4, "REG_DMA3SAD"),
        new DsIoRegister(0x040000d8, "REG_DMA3DAD"),
        new DsIoRegister(0x040000dc, "REG_DMA3CNT_L"),
        new DsIoRegister(0x040000de, "REG_DMA3CNT_H"),
        new DsIoRegister(0x040000e0, "REG_DMA0FILL"),
        new DsIoRegister(0x040000e4, "REG_DMA1FILL"),
        new DsIoRegister(0x040000e8, "REG_DMA2FILL"),
        new DsIoRegister(0x040000ec, "REG_DMA3FILL"),
        new DsIoRegister(0x04000100, "REG_TIM0CNT_L"),
        new DsIoRegister(0x04000102, "REG_TIM0CNT_H"),
        new DsIoRegister(0x04000104, "REG_TIM1CNT_L"),
        new DsIoRegister(0x04000106, "REG_TIM1CNT_H"),
        new DsIoRegister(0x04000108, "REG_TIM2CNT_L"),
        new DsIoRegister(0x0400010a, "REG_TIM2CNT_H"),
        new DsIoRegister(0x0400010c, "REG_TIM3CNT_L"),
        new DsIoRegister(0x0400010e, "REG_TIM3CNT_H"),
        new DsIoRegister(0x04000130, "REG_KEYINPUT"),
        new DsIoRegister(0x04000132, "REG_KEYCNT"),
        new DsIoRegister(0x04000180, "REG_IPC_SYNC"),
        new DsIoRegister(0x04000184, "REG_IPC_FIFO_CTRL"),
        new DsIoRegister(0x04000188, "REG_IPC_FIFO_SEND"),
        new DsIoRegister(0x040001a0, "REG_AUX_SPI_CNT"),
        new DsIoRegister(0x040001a2, "REG_AUX_SPI_DATA"),
        new DsIoRegister(0x040001a4, "REG_ROM_CNT"),
        new DsIoRegister(0x040001a8, "REG_CARD_COMMAND"),
        new DsIoRegister(0x040001b0, "REG_CARD_SEED0_L"),
        new DsIoRegister(0x040001b4, "REG_CARD_SEED1_L"),
        new DsIoRegister(0x040001b8, "REG_CARD_SEED0_H"),
        new DsIoRegister(0x040001ba, "REG_CARD_SEED1_H"),
        new DsIoRegister(0x04000204, "REG_EXMEM_CNT"),
        new DsIoRegister(0x04000208, "REG_IME"),
        new DsIoRegister(0x04000210, "REG_IE"),
        new DsIoRegister(0x04000214, "REG_IF"),
        new DsIoRegister(0x04000240, "REG_VRAM_CNT_A"),
        new DsIoRegister(0x04000241, "REG_VRAM_CNT_B"),
        new DsIoRegister(0x04000242, "REG_VRAM_CNT_C"),
        new DsIoRegister(0x04000243, "REG_VRAM_CNT_D"),
        new DsIoRegister(0x04000244, "REG_VRAM_CNT_E"),
        new DsIoRegister(0x04000245, "REG_VRAM_CNT_F"),
        new DsIoRegister(0x04000246, "REG_VRAM_CNT_G"),
        new DsIoRegister(0x04000247, "REG_WRAM_CNT"),
        new DsIoRegister(0x04000248, "REG_VRAM_CNT_H"),
        new DsIoRegister(0x04000249, "REG_VRAM_CNT_I"),
        new DsIoRegister(0x04000280, "REG_DIV_CNT"),
        new DsIoRegister(0x04000290, "REG_DIV_NUMER"),
        new DsIoRegister(0x04000298, "REG_DIV_DENOM"),
        new DsIoRegister(0x040002a0, "REG_DIV_RESULT"),
        new DsIoRegister(0x040002a8, "REG_REM_RESULT"),
        new DsIoRegister(0x040002b0, "REG_SQRT_CNT"),
        new DsIoRegister(0x040002b4, "REG_SQRT_RESULT"),
        new DsIoRegister(0x040002b8, "REG_SQRT_PARAM"),
        new DsIoRegister(0x04000300, "REG_POST_FLAG"),
        new DsIoRegister(0x04000304, "REG_POWER_CNT"),
        new DsIoRegister(0x04000320, "REG_GFX_RDLINES_COUNT"),
        new DsIoRegister(0x04000330, "REG_GFX_EDGE_TABLE"),
        new DsIoRegister(0x04000340, "REG_GFX_ALPHA_TEST_REF"),
        new DsIoRegister(0x04000350, "REG_GFX_CLEAR_COLOR"),
        new DsIoRegister(0x04000354, "REG_GFX_CLEAR_DEPTH"),
        new DsIoRegister(0x04000356, "REG_GFX_CLRIMAGE_OFFSET"),
        new DsIoRegister(0x04000358, "REG_GFX_FOG_COLOR"),
        new DsIoRegister(0x0400035c, "REG_GFX_FOG_OFFSET"),
        new DsIoRegister(0x04000360, "REG_GFX_FOG_TABLE"),
        new DsIoRegister(0x04000380, "REG_GFX_TOON_TABLE"),
        new DsIoRegister(0x04000400, "REG_GFX_FIFO"),
        new DsIoRegister(0x04000440, "GFX_FIFO_MATRIX_MODE"),
        new DsIoRegister(0x04000444, "GFX_FIFO_MATRIX_PUSH"),
        new DsIoRegister(0x04000448, "GFX_FIFO_MATRIX_POP"),
        new DsIoRegister(0x0400044c, "GFX_FIFO_MATRIX_STORE"),
        new DsIoRegister(0x04000450, "GFX_FIFO_MATRIX_RESTORE"),
        new DsIoRegister(0x04000454, "GFX_FIFO_MATRIX_IDENTITY"),
        new DsIoRegister(0x04000458, "GFX_FIFO_MATRIX_LOAD_4x4"),
        new DsIoRegister(0x0400045c, "GFX_FIFO_MATRIX_LOAD_4x3"),
        new DsIoRegister(0x04000460, "GFX_FIFO_MATRIX_MULT_4x4"),
        new DsIoRegister(0x04000464, "GFX_FIFO_MATRIX_MULT_4x3"),
        new DsIoRegister(0x04000468, "GFX_FIFO_MATRIX_MULT_3x3"),
        new DsIoRegister(0x0400046c, "GFX_FIFO_MATRIX_SCALE"),
        new DsIoRegister(0x04000470, "GFX_FIFO_MATRIX_TRANSLATE"),
        new DsIoRegister(0x04000480, "GFX_FIFO_VERTEX_COLOR"),
        new DsIoRegister(0x04000484, "GFX_FIFO_VERTEX_NORMAL"),
        new DsIoRegister(0x04000488, "GFX_FIFO_VERTEX_TEXCOORD"),
        new DsIoRegister(0x0400048c, "GFX_FIFO_VERTEX_16"),
        new DsIoRegister(0x04000490, "GFX_FIFO_VERTEX_10"),
        new DsIoRegister(0x04000494, "GFX_FIFO_VERTEX_XY"),
        new DsIoRegister(0x04000498, "GFX_FIFO_VERTEX_XZ"),
        new DsIoRegister(0x0400049c, "GFX_FIFO_VERTEX_YZ"),
        new DsIoRegister(0x040004a0, "GFX_FIFO_VERTEX_10_DELTA"),
        new DsIoRegister(0x040004a4, "GFX_FIFO_POLYGON_ATTR"),
        new DsIoRegister(0x040004a8, "GFX_FIFO_TEXTURE_PARAM"),
        new DsIoRegister(0x040004ac, "GFX_FIFO_TEXTURE_PALETTE"),
        new DsIoRegister(0x040004c0, "GFX_FIFO_MATERIAL_DIFFUSE_AMBIENT"),
        new DsIoRegister(0x040004c4, "GFX_FIFO_MATERIAL_SPECULAR_EMISSION"),
        new DsIoRegister(0x040004c8, "GFX_FIFO_LIGHT_DIRECTION"),
        new DsIoRegister(0x040004cc, "GFX_FIFO_LIGHT_COLOR"),
        new DsIoRegister(0x040004d0, "GFX_FIFO_SHININESS_TABLE"),
        new DsIoRegister(0x04000500, "GFX_FIFO_POLYGONS_BEGIN"),
        new DsIoRegister(0x04000504, "GFX_FIFO_POLYGONS_END"),
        new DsIoRegister(0x04000540, "GFX_FIFO_SWAP_BUFFERS"),
        new DsIoRegister(0x04000580, "GFX_FIFO_VIEWPORT"),
        new DsIoRegister(0x040005c0, "GFX_FIFO_TEST_BOX"),
        new DsIoRegister(0x040005c4, "GFX_FIFO_TEST_POS"),
        new DsIoRegister(0x040005c8, "GFX_FIFO_TEST_VEC"),
        new DsIoRegister(0x04000600, "REG_GFX_STATUS"),
        new DsIoRegister(0x04000604, "REG_GFX_RAM_COUNT"),
        new DsIoRegister(0x04000610, "REG_GFX_CUTOFF_DEPTH"),
        new DsIoRegister(0x04000620, "REG_GFX_RESULT_POS"),
        new DsIoRegister(0x04000630, "REG_GFX_RESULT_VEC"),
        new DsIoRegister(0x04000640, "REG_GFX_RESULT_CLIP_MATRIX"),
        new DsIoRegister(0x04000680, "REG_GFX_RESULT_VEC_MATRIX"),
        new DsIoRegister(0x04001000, "REG_DISPCNT_SUB"),
        new DsIoRegister(0x04001008, "REG_BG0CNT_SUB"),
        new DsIoRegister(0x0400100a, "REG_BG1CNT_SUB"),
        new DsIoRegister(0x0400100c, "REG_BG2CNT_SUB"),
        new DsIoRegister(0x0400100e, "REG_BG3CNT_SUB"),
        new DsIoRegister(0x04001010, "REG_BG0HOFS_SUB"),
        new DsIoRegister(0x04001012, "REG_BG0VOFS_SUB"),
        new DsIoRegister(0x04001014, "REG_BG1HOFS_SUB"),
        new DsIoRegister(0x04001016, "REG_BG1VOFS_SUB"),
        new DsIoRegister(0x04001018, "REG_BG2HOFS_SUB"),
        new DsIoRegister(0x0400101a, "REG_BG2VOFS_SUB"),
        new DsIoRegister(0x0400101c, "REG_BG3HOFS_SUB"),
        new DsIoRegister(0x0400101e, "REG_BG3VOFS_SUB"),
        new DsIoRegister(0x04001020, "REG_BG2PA_SUB"),
        new DsIoRegister(0x04001022, "REG_BG2PB_SUB"),
        new DsIoRegister(0x04001024, "REG_BG2PC_SUB"),
        new DsIoRegister(0x04001026, "REG_BG2PD_SUB"),
        new DsIoRegister(0x04001028, "REG_BG2X_SUB"),
        new DsIoRegister(0x0400102c, "REG_BG2Y_SUB"),
        new DsIoRegister(0x04001030, "REG_BG3PA_SUB"),
        new DsIoRegister(0x04001032, "REG_BG3PB_SUB"),
        new DsIoRegister(0x04001034, "REG_BG3PC_SUB"),
        new DsIoRegister(0x04001036, "REG_BG3PD_SUB"),
        new DsIoRegister(0x04001038, "REG_BG3X_SUB"),
        new DsIoRegister(0x0400103c, "REG_BG3Y_SUB"),
        new DsIoRegister(0x04001040, "REG_WIN0H_SUB"),
        new DsIoRegister(0x04001042, "REG_WIN1H_SUB"),
        new DsIoRegister(0x04001044, "REG_WIN0V_SUB"),
        new DsIoRegister(0x04001046, "REG_WIN1V_SUB"),
        new DsIoRegister(0x04001048, "REG_WININ_SUB"),
        new DsIoRegister(0x0400104a, "REG_WINOUT_SUB"),
        new DsIoRegister(0x0400104c, "REG_MOSAIC_SUB"),
        new DsIoRegister(0x04001050, "REG_BLDCNT_SUB"),
        new DsIoRegister(0x04001052, "REG_BLDALPHA_SUB"),
        new DsIoRegister(0x04001054, "REG_BLDY_SUB"),
        new DsIoRegister(0x0400106c, "REG_MASTER_BRIGHT_SUB"),
        new DsIoRegister(0x04100000, "REG_IPC_FIFO_RECV"),
        new DsIoRegister(0x04100010, "REG_CARD_DATA_READ"),
    };

    public static final @NotNull DsIoRegister[] ARM7_REGS = {
        new DsIoRegister(0x04000004, "REG_DISPCNT"),
        new DsIoRegister(0x04000006, "REG_VCOUNT"),
        new DsIoRegister(0x040000b0, "REG_DMA0SAD"),
        new DsIoRegister(0x040000b4, "REG_DMA0DAD"),
        new DsIoRegister(0x040000b8, "REG_DMA0CNT_L"),
        new DsIoRegister(0x040000ba, "REG_DMA0CNT_H"),
        new DsIoRegister(0x040000bc, "REG_DMA1SAD"),
        new DsIoRegister(0x040000c0, "REG_DMA1DAD"),
        new DsIoRegister(0x040000c4, "REG_DMA1CNT_L"),
        new DsIoRegister(0x040000c6, "REG_DMA1CNT_H"),
        new DsIoRegister(0x040000c8, "REG_DMA2SAD"),
        new DsIoRegister(0x040000cc, "REG_DMA2DAD"),
        new DsIoRegister(0x040000d0, "REG_DMA2CNT_L"),
        new DsIoRegister(0x040000d2, "REG_DMA2CNT_H"),
        new DsIoRegister(0x040000d4, "REG_DMA3SAD"),
        new DsIoRegister(0x040000d8, "REG_DMA3DAD"),
        new DsIoRegister(0x040000dc, "REG_DMA3CNT_L"),
        new DsIoRegister(0x040000de, "REG_DMA3CNT_H"),
        new DsIoRegister(0x040000e0, "REG_DMA0FILL"),
        new DsIoRegister(0x040000e4, "REG_DMA1FILL"),
        new DsIoRegister(0x040000e8, "REG_DMA2FILL"),
        new DsIoRegister(0x040000ec, "REG_DMA3FILL"),
        new DsIoRegister(0x04000130, "REG_KEYINPUT"),
        new DsIoRegister(0x04000132, "REG_KEYCNT"),
        new DsIoRegister(0x04000180, "REG_IPC_SYNC"),
        new DsIoRegister(0x04000184, "REG_IPC_FIFO_CTRL"),
        new DsIoRegister(0x04000188, "REG_IPC_FIFO_SEND"),
        new DsIoRegister(0x040001a0, "REG_AUX_SPI_CNT"),
        new DsIoRegister(0x040001a2, "REG_AUX_SPI_DATA"),
        new DsIoRegister(0x040001a4, "REG_ROM_CNT"),
        new DsIoRegister(0x040001a8, "REG_CARD_COMMAND"),
        new DsIoRegister(0x040001b0, "REG_CARD_SEED0_L"),
        new DsIoRegister(0x040001b4, "REG_CARD_SEED1_L"),
        new DsIoRegister(0x040001b8, "REG_CARD_SEED0_H"),
        new DsIoRegister(0x040001ba, "REG_CARD_SEED1_H"),
        new DsIoRegister(0x040001c0, "REG_SPI_CNT"),
        new DsIoRegister(0x040001c2, "REG_SPI_DATA"),
        new DsIoRegister(0x04000204, "REG_EXMEM_CNT"),
        new DsIoRegister(0x04000206, "REG_WIFI_WAIT_CNT"),
        new DsIoRegister(0x04000208, "REG_IME"),
        new DsIoRegister(0x04000210, "REG_IE"),
        new DsIoRegister(0x04000214, "REG_IF"),
        new DsIoRegister(0x04000240, "REG_VRAM_STAT"),
        new DsIoRegister(0x04000241, "REG_WRAM_STAT"),
        new DsIoRegister(0x04000300, "REG_POST_FLAG"),
        new DsIoRegister(0x04000304, "REG_POWER_CNT"),
        new DsIoRegister(0x04000308, "REG_BIOS_PROT"),
        new DsIoRegister(0x04000400, "REG_SOUND0_CNT"),
        new DsIoRegister(0x04000404, "REG_SOUND0_SRC"),
        new DsIoRegister(0x04000408, "REG_SOUND0_TIMER"),
        new DsIoRegister(0x0400040a, "REG_SOUND0_LOOP"),
        new DsIoRegister(0x0400040c, "REG_SOUND0_LEN"),
        new DsIoRegister(0x04000410, "REG_SOUND1_CNT"),
        new DsIoRegister(0x04000414, "REG_SOUND1_SRC"),
        new DsIoRegister(0x04000418, "REG_SOUND1_TIMER"),
        new DsIoRegister(0x0400041a, "REG_SOUND1_LOOP"),
        new DsIoRegister(0x0400041c, "REG_SOUND1_LEN"),
        new DsIoRegister(0x04000420, "REG_SOUND2_CNT"),
        new DsIoRegister(0x04000424, "REG_SOUND2_SRC"),
        new DsIoRegister(0x04000428, "REG_SOUND2_TIMER"),
        new DsIoRegister(0x0400042a, "REG_SOUND2_LOOP"),
        new DsIoRegister(0x0400042c, "REG_SOUND2_LEN"),
        new DsIoRegister(0x04000430, "REG_SOUND3_CNT"),
        new DsIoRegister(0x04000434, "REG_SOUND3_SRC"),
        new DsIoRegister(0x04000438, "REG_SOUND3_TIMER"),
        new DsIoRegister(0x0400043a, "REG_SOUND3_LOOP"),
        new DsIoRegister(0x0400043c, "REG_SOUND3_LEN"),
        new DsIoRegister(0x04000440, "REG_SOUND4_CNT"),
        new DsIoRegister(0x04000444, "REG_SOUND4_SRC"),
        new DsIoRegister(0x04000448, "REG_SOUND4_TIMER"),
        new DsIoRegister(0x0400044a, "REG_SOUND4_LOOP"),
        new DsIoRegister(0x0400044c, "REG_SOUND4_LEN"),
        new DsIoRegister(0x04000450, "REG_SOUND5_CNT"),
        new DsIoRegister(0x04000454, "REG_SOUND5_SRC"),
        new DsIoRegister(0x04000458, "REG_SOUND5_TIMER"),
        new DsIoRegister(0x0400045a, "REG_SOUND5_LOOP"),
        new DsIoRegister(0x0400045c, "REG_SOUND5_LEN"),
        new DsIoRegister(0x04000460, "REG_SOUND6_CNT"),
        new DsIoRegister(0x04000464, "REG_SOUND6_SRC"),
        new DsIoRegister(0x04000468, "REG_SOUND6_TIMER"),
        new DsIoRegister(0x0400046a, "REG_SOUND6_LOOP"),
        new DsIoRegister(0x0400046c, "REG_SOUND6_LEN"),
        new DsIoRegister(0x04000470, "REG_SOUND7_CNT"),
        new DsIoRegister(0x04000474, "REG_SOUND7_SRC"),
        new DsIoRegister(0x04000478, "REG_SOUND7_TIMER"),
        new DsIoRegister(0x0400047a, "REG_SOUND7_LOOP"),
        new DsIoRegister(0x0400047c, "REG_SOUND7_LEN"),
        new DsIoRegister(0x04000480, "REG_SOUND8_CNT"),
        new DsIoRegister(0x04000484, "REG_SOUND8_SRC"),
        new DsIoRegister(0x04000488, "REG_SOUND8_TIMER"),
        new DsIoRegister(0x0400048a, "REG_SOUND8_LOOP"),
        new DsIoRegister(0x0400048c, "REG_SOUND8_LEN"),
        new DsIoRegister(0x04000490, "REG_SOUND9_CNT"),
        new DsIoRegister(0x04000494, "REG_SOUND9_SRC"),
        new DsIoRegister(0x04000498, "REG_SOUND9_TIMER"),
        new DsIoRegister(0x0400049a, "REG_SOUND9_LOOP"),
        new DsIoRegister(0x0400049c, "REG_SOUND9_LEN"),
        new DsIoRegister(0x040004a0, "REG_SOUND10_CNT"),
        new DsIoRegister(0x040004a4, "REG_SOUND10_SRC"),
        new DsIoRegister(0x040004a8, "REG_SOUND10_TIMER"),
        new DsIoRegister(0x040004aa, "REG_SOUND10_LOOP"),
        new DsIoRegister(0x040004ac, "REG_SOUND10_LEN"),
        new DsIoRegister(0x040004b0, "REG_SOUND11_CNT"),
        new DsIoRegister(0x040004b4, "REG_SOUND11_SRC"),
        new DsIoRegister(0x040004b8, "REG_SOUND11_TIMER"),
        new DsIoRegister(0x040004ba, "REG_SOUND11_LOOP"),
        new DsIoRegister(0x040004bc, "REG_SOUND11_LEN"),
        new DsIoRegister(0x040004c0, "REG_SOUND12_CNT"),
        new DsIoRegister(0x040004c4, "REG_SOUND12_SRC"),
        new DsIoRegister(0x040004c8, "REG_SOUND12_TIMER"),
        new DsIoRegister(0x040004ca, "REG_SOUND12_LOOP"),
        new DsIoRegister(0x040004cc, "REG_SOUND12_LEN"),
        new DsIoRegister(0x040004d0, "REG_SOUND13_CNT"),
        new DsIoRegister(0x040004d4, "REG_SOUND13_SRC"),
        new DsIoRegister(0x040004d8, "REG_SOUND13_TIMER"),
        new DsIoRegister(0x040004da, "REG_SOUND13_LOOP"),
        new DsIoRegister(0x040004dc, "REG_SOUND13_LEN"),
        new DsIoRegister(0x040004e0, "REG_SOUND14_CNT"),
        new DsIoRegister(0x040004e4, "REG_SOUND14_SRC"),
        new DsIoRegister(0x040004e8, "REG_SOUND14_TIMER"),
        new DsIoRegister(0x040004ea, "REG_SOUND14_LOOP"),
        new DsIoRegister(0x040004ec, "REG_SOUND14_LEN"),
        new DsIoRegister(0x040004f0, "REG_SOUND15_CNT"),
        new DsIoRegister(0x040004f4, "REG_SOUND15_SRC"),
        new DsIoRegister(0x040004f8, "REG_SOUND15_TIMER"),
        new DsIoRegister(0x040004fa, "REG_SOUND15_LOOP"),
        new DsIoRegister(0x040004fc, "REG_SOUND15_LEN"),
        new DsIoRegister(0x04000500, "REG_SOUND_CNT"),
        new DsIoRegister(0x04000504, "REG_SOUND_BIAS"),
        new DsIoRegister(0x04000508, "REG_SOUND_CAP0_CNT"),
        new DsIoRegister(0x04000509, "REG_SOUND_CAP1_CNT"),
        new DsIoRegister(0x04000510, "REG_SOUND_CAP0_DEST"),
        new DsIoRegister(0x04000514, "REG_SOUND_CAP0_LEN"),
        new DsIoRegister(0x04000518, "REG_SOUND_CAP1_DEST"),
        new DsIoRegister(0x0400051c, "REG_SOUND_CAP1_LEN"),
        new DsIoRegister(0x04100000, "REG_IPC_FIFO_RECV"),
        new DsIoRegister(0x04100010, "REG_CARD_DATA_READ"),
        new DsIoRegister(0x04800000, "REG_WIFI"),
    };

    public static final @NotNull DsIoRegister[] BIOS_REGS = {
        new DsIoRegister(0x027ffc40, "BIOS_BOOT_INDICATOR"),
    };
}
