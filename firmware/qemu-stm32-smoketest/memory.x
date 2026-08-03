/* STM32F405-class memory map (QEMU's `netduinoplus2` machine, Cortex-M4F - matches the
   thumbv7em-none-eabihf target added in T-116). Conservative real-hardware sizes; this smoke
   test uses a tiny fraction of either region. */
MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 1024K
  RAM : ORIGIN = 0x20000000, LENGTH = 128K
}
