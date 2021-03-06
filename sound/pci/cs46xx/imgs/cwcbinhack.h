
#ifndef __HEADER_cwcbinhack_H__
#define __HEADER_cwcbinhack_H__

static struct dsp_symbol_entry cwcbinhack_symbols[] = {
  { 0x02c8, "OVERLAYBEGINADDRESS",0x00 },
  { 0x02c8, "MAGICSNOOPTASK",0x03 },
  { 0x0308, "#CODE_END",0x00 },
}; 

static u32 cwcbinhack_code[] = {
  
  0x0007bfb0,0x000bc240,0x00000c2e,0x000c6084, 
  0x000b8630,0x00001016,0x00006408,0x000efb84, 
  0x00016008,0x00000000,0x0001c088,0x000c0000, 
  0x000fc908,0x000e3392,0x0005f488,0x000efb84, 
  0x0001d402,0x000b2e00,0x0003d418,0x00001000, 
  0x0008d574,0x000c4293,0x00065625,0x000ea30e, 
  0x00096c01,0x000c6f92,0x0001a58a,0x000c6085, 
  0x00002f43,0x00000000,0x000e03a0,0x00001016, 
  0x0005e608,0x000c0000,0x00000000,0x00000000, 
  0x000ca108,0x000dcca1,0x00003bac,0x000c3205, 
  0x00073843,0x00000000,0x00010730,0x00001017, 
  0x0001600a,0x000c0000,0x00057488,0x00000000, 
  0x00000000,0x000e5084,0x00000000,0x000eba44, 
  0x00087401,0x000e4782,0x00000734,0x00001000, 
  0x00010705,0x000a6880,0x00006a88,0x000c75c4, 
  0x00000000,0x00000000,0x00000000,0x00000000, 
};

static struct dsp_segment_desc cwcbinhack_segments[] = {
  { SEGTYPE_SP_PROGRAM, 0x00000000, 64, cwcbinhack_code },
};

static struct dsp_module_desc cwcbinhack_module = {
  "cwcbinhack",
  {
    3,
    cwcbinhack_symbols
  },
  1,
  cwcbinhack_segments,
};

#endif 
