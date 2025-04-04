SECTIONS
{

  . = 0x80000000; /* Base address */
  PROVIDE(_stext = .); /* Optional: Symbol for text start */
  .text.init : { *(.text.init) }
  .tohost ALIGN(0x1000) : { *(.tohost) }
  .text : { *(.text) }
  PROVIDE(_etext = .); /* Optional: Symbol for text end */


  /* data segment */
  PROVIDE(_sdata = .); /* Optional: Symbol for data start */
  .data ALIGN(0x40) : { *(.data) }

  .sdata : {
    __global_pointer$ = . + 0x800;
    *(.srodata.cst16) *(.srodata.cst8) *(.srodata.cst4) *(.srodata.cst2) *(.srodata*)
    *(.sdata .sdata.* .gnu.linkonce.s.*)
  }
  PROVIDE(_edata = .); /* Optional: Symbol for data end */

  .sbss : {
    *(.sbss .sbss.* .gnu.linkonce.sb.*)
    *(.scommon)
  }
  PROVIDE(_sbss = .); /* Optional: Symbol for BSS start */
  .bss ALIGN(0x40) : { *(.bss) }
  PROVIDE(_ebss = .); /* Optional: Symbol for BSS end */


  /* thread-local data segment */
  .tdata :
  {
    _tls_data = .;
    *(.tdata.begin)
    *(.tdata)
    *(.tdata.end)
  }
  .tbss :
  {
    *(.tbss)
    *(.tbss.end)
  }

  /*
   * Section dedicated to "kernel" read-only data
   */
  .krodata ALIGN(0x40) : {
    PROVIDE(_krodata_start = .); /* Add start symbol */
    KEEP(*(.krodata))
    PROVIDE(_krodata_end = .);   /* Add end symbol */
  }

  /* End of uninitialized data segment */
  _end = .;
  PROVIDE(end = .); /* Ensure 'end' symbol is available if needed */
}