/*======================================================================*/
/* Proxy kernel linker script - RWX memory                              */
/*======================================================================*/

/* Indichiamo l’architettura */
OUTPUT_ARCH("riscv")
ENTRY(_start)

/*----------------------------------------------------------------------*/
/* Definizione di un unico banco di memoria RWX                         */
/*----------------------------------------------------------------------*/
MEMORY
{
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 0x01000000
  /* 
   * Ad esempio 16 MB di RAM dal 0x80000000 in poi.
   * Regola LENGTH in base alle tue esigenze. 
   */
}

/*----------------------------------------------------------------------*/
/* Mappatura delle sezioni                                              */
/*----------------------------------------------------------------------*/
SECTIONS
{
  /* Indichiamo la posizione iniziale (facoltativo, 
     perché . = ORIGIN(RAM) farà la stessa cosa) */
  . = ORIGIN(RAM);

  /* Sezione .text.init */
  .text.init : 
  {
    *(.text.init)
  } > RAM

  /* Sezione .tohost allineata a 0x1000 */
  .tohost ALIGN(0x1000) : 
  {
    *(.tohost)
  } > RAM

  /* Sezione .text "normale" */
  .text : 
  {
    *(.text)
  } > RAM

  /* Sezione .data con allineamento a 0x40 */
  .data ALIGN(0x40) : 
  {
    *(.data)
  } > RAM

  /* Sezione .sdata */
  .sdata : 
  {
    __global_pointer$ = . + 0x800;
    *(.srodata.cst16)
    *(.srodata.cst8)
    *(.srodata.cst4)
    *(.srodata.cst2)
    *(.srodata*)
    *(.sdata .sdata.* .gnu.linkonce.s.*)
  } > RAM

  /* Sezione .sbss */
  .sbss : 
  {
    *(.sbss .sbss.* .gnu.linkonce.sb.*)
    *(.scommon)
  } > RAM

  /* Sezione .bss con allineamento a 0x40 */
  .bss ALIGN(0x40) : 
  {
    *(.bss)
  } > RAM

  /* Thread-local data */
  .tdata :
  {
    _tls_data = .;
    *(.tdata.begin)
    *(.tdata)
    *(.tdata.end)
  } > RAM

  .tbss :
  {
    *(.tbss)
    *(.tbss.end)
  } > RAM

  /* Fine dei segmenti non inizializzati */
  _end = .;
}

