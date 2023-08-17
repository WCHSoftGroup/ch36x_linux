#ifndef _CH36X_LIB_H
#define _CH36X_LIB_H

#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>

enum CHIP_TYPE {
	CHIP_CH365 = 1,
	CHIP_CH367,
	CHIP_CH368
};

enum INTMODE {
	INT_NONE = 0,
	INT_LOW,
	INT_HIGH,
	INT_RISING,
	INT_FALLING
};

#define BIT(i) (1 << i)

#define SIZE_BYTE  0x01
#define SIZE_WORD  0x02
#define SIZE_DWORD 0x03

#define IOCTL_MAGIC		'P'
#define CH36x_GET_IO_BASE_ADDR	_IOR(IOCTL_MAGIC, 0x80, uint16_t)
#define CH36x_GET_MEM_BASE_ADDR _IOR(IOCTL_MAGIC, 0x81, uint16_t)

/* io/mem rw codes */
#define CH36x_READ_CONFIG_BYTE	 _IOR(IOCTL_MAGIC, 0x82, uint16_t)
#define CH36x_READ_CONFIG_WORD	 _IOR(IOCTL_MAGIC, 0x83, uint16_t)
#define CH36x_READ_CONFIG_DWORD	 _IOR(IOCTL_MAGIC, 0x84, uint16_t)
#define CH36x_WRITE_CONFIG_BYTE	 _IOW(IOCTL_MAGIC, 0x85, uint16_t)
#define CH36x_WRITE_CONFIG_WORD	 _IOW(IOCTL_MAGIC, 0x86, uint16_t)
#define CH36x_WRITE_CONFIG_DWORD _IOW(IOCTL_MAGIC, 0x87, uint16_t)

#define CH36x_READ_IO_BYTE   _IOR(IOCTL_MAGIC, 0x88, uint16_t)
#define CH36x_READ_IO_WORD   _IOR(IOCTL_MAGIC, 0x89, uint16_t)
#define CH36x_READ_IO_DWORD  _IOR(IOCTL_MAGIC, 0x8a, uint16_t)
#define CH36x_WRITE_IO_BYTE  _IOW(IOCTL_MAGIC, 0x8b, uint16_t)
#define CH36x_WRITE_IO_WORD  _IOW(IOCTL_MAGIC, 0x8c, uint16_t)
#define CH36x_WRITE_IO_DWORD _IOW(IOCTL_MAGIC, 0x8d, uint16_t)

#define CH36x_READ_MEM_BYTE   _IOR(IOCTL_MAGIC, 0x8e, uint16_t)
#define CH36x_READ_MEM_WORD   _IOR(IOCTL_MAGIC, 0x8f, uint16_t)
#define CH36x_READ_MEM_DWORD  _IOR(IOCTL_MAGIC, 0x90, uint16_t)
#define CH36x_WRITE_MEM_BYTE  _IOW(IOCTL_MAGIC, 0x91, uint16_t)
#define CH36x_WRITE_MEM_WORD  _IOW(IOCTL_MAGIC, 0x92, uint16_t)
#define CH36x_WRITE_MEM_DWORD _IOW(IOCTL_MAGIC, 0x93, uint16_t)
#define CH36x_READ_MEM_BLOCK  _IOR(IOCTL_MAGIC, 0x94, uint16_t)
#define CH36x_WRITE_MEM_BLOCK _IOW(IOCTL_MAGIC, 0x95, uint16_t)

/* interrupt codes */
#define CH36x_ENABLE_INT  _IOW(IOCTL_MAGIC, 0x96, uint16_t)
#define CH36x_DISABLE_INT _IOW(IOCTL_MAGIC, 0x97, uint16_t)
#define CH36x_GET_IRQ	  _IOR(IOCTL_MAGIC, 0xa0, uint16_t)

/* other codes */
#define CH36x_GET_CHIPTYPE _IOR(IOCTL_MAGIC, 0x98, uint16_t)
#define CH36x_GET_VERSION  _IOR(IOCTL_MAGIC, 0x99, uint16_t)
#define CH36x_SET_STREAM   _IOW(IOCTL_MAGIC, 0x9a, uint16_t)
#define CH36x_STREAM_SPI   _IOWR(IOCTL_MAGIC, 0x9b, uint16_t)
#define CH36x_FLASH_LOCK   _IOW(IOCTL_MAGIC, 0x9c, uint16_t)
#define CH36x_FLASH_ERASE  _IOW(IOCTL_MAGIC, 0x9d, uint16_t)
#define CH36x_FLASH_READ   _IOWR(IOCTL_MAGIC, 0x9e, uint16_t)
#define CH36x_FLASH_WRITE  _IOW(IOCTL_MAGIC, 0x9f, uint16_t)

/* IOCTRL register bits */
#define CH365_IOCTRL_A15_BIT	BIT(0) /* Set A15 */
#define CH365_IOCTRL_SYS_EX_BIT BIT(1) /* Set SYS_EX */
#define CH365_IOCTRL_INTA_BIT	BIT(2) /* INT Active status */

/* MICSR register bits */
#define CH367_MICSR_GPO_BIT  BIT(0) /* Set GPO */
#define CH367_MICSR_INTA_BIT BIT(2) /* INT Active status */
#define CH367_MICSR_INTS_BIT BIT(3) /* INT status */
#define CH367_MICSR_RSTO_BIT BIT(7) /* Set RSTO */

/* INTCR register bits */
#define CH367_INTCR_MSI_ENABLE_BIT BIT(0) /* MSI Enable */
#define CH367_INTCR_INT_ENABLE_BIT BIT(1) /* Global INT Enable */
#define CH367_INTCR_INT_POLAR_BIT  BIT(2) /* Set INT Polar */
#define CH367_INTCR_INT_TYPE_BIT   BIT(3) /* Set INT Type */
#define CH367_INTCR_INT_RETRY_BIT  BIT(4) /* Set INT Retry */

/* GPOR register bits */
#define CH367_GPOR_SET_SDA_BIT	   BIT(0) /* Set SDA Value */
#define CH367_GPOR_SET_SCL_BIT	   BIT(1) /* Set SCL Value */
#define CH367_GPOR_SET_SCS_BIT	   BIT(2) /* Set SCS Value */
#define CH367_GPOR_ENABLE_WAKE_BIT BIT(5) /* Force Wakeup Support */
#define CH367_GPOR_SET_SDX_DIR_BIT BIT(6) /* Set SDX Direction */
#define CH367_GPOR_SET_SDX_BIT	   BIT(7) /* Set SDX Value */

/* SPICR register bits */
#define CH367_SPICR_SPI_status_BIT  BIT(4) /* SPI Transfer Ongoing status */
#define CH367_SPICR_SPI_FREQ_BIT    BIT(5) /* Set SPI Freq: 1->15.6MHz 0->31.3MHz */
#define CH367_SPICR_SPI_SLT_SDI_BIT BIT(6) /* Set SPI Data In Pin: 1->SDI 0->SDX */
#define CH367_SPICR_SPI_NEWTRAN_BIT BIT(7) /* Begin New Transfer After Read SPIDR */

typedef struct _CH365_IO_REG {	    // CH365 IO space
	uint8_t mCh365IoPort[0xf0]; // 00H-EFH, 240 bytes standard IO bytes
	union {
		uint16_t mCh365MemAddr; // F0H Memory Interface: A15-A0 address setting register
		struct {
			uint8_t mCh365MemAddrL; // F0H Memory Interface: A7-A0 address setting register
			uint8_t mCh365MemAddrH; // F1H Memory Interface: A15-A8 address setting register
		};
	};
	uint8_t mCh365IoResv2;	  // F2H
	uint8_t mCh365MemData;	  // F3H Memory Interface: Memory data access register
	uint8_t mCh365I2cData;	  // F4H I2C Interface: I2C data access register
	uint8_t mCh365I2cCtrl;	  // F5H I2C Interface: I2C control and status register
	uint8_t mCh365I2cAddr;	  // F6H I2C Interface: I2C address setting register
	uint8_t mCh365I2cDev;	  // F7H I2C Interface: I2C device address and command register
	uint8_t mCh365IoCtrl;	  // F8H Control register, high 5 bits are read-only
	uint8_t mCh365IoBuf;	  // F9H Local data input buffer register
	uint8_t mCh365Speed;	  // FAH Speed control register
	uint8_t mCh365IoResv3;	  // FBH
	uint8_t mCh365IoTime;	  // FCH Hardware loop count register
	uint8_t mCh365IoResv4[3]; // FDH
} mCH365_IO_REG, *mPCH365_IO_REG;

typedef struct _CH365_MEM_REG {	       // CH365 Memory space
	uint8_t mCh365MemPort[0x8000]; // 0000H-7FFFH, 32768 bytes in total
} mCH365_MEM_REG, *mPCH365_MEM_REG;

typedef struct _CH367_IO_REG {	    // CH367 IO space
	uint8_t mCH367IoPort[0xE8]; // 00H-E7H, 232 bytes standard IO bytes
	uint8_t mCH367GPOR;	    // E8H General output register
	uint8_t mCH367GPVR;	    // E9H General variable register
	uint8_t mCH367GPIR;	    // EAH General input register
	uint8_t mCH367IntCtr;	    // EBH Interrupt control register
	union {
		uint8_t mCH367IoBuf8;	// ECH 8-bit passive parallel interface data buffer
		uint32_t mCH367IoBuf32; // ECH 32-bit passive parallel interface data buffer
	};
	union {
		uint16_t mCH368MemAddr; // F0H Memory Interface: A15-A0 address setting register
		struct {
			uint8_t mCH368MemAddrL; // F0H Memory Interface: A7-A0 address setting register
			union {
				uint8_t mCH368MemAddrH; // F1H Memory Interface: A15-A8 address setting register
				uint8_t mCH367GPOR2;	// F1H General output register 2
			};
		} ASR;
	};
	uint8_t mCH367IORESV2; // F2H
	uint8_t mCH368MemData; // F3H Memory Interface: Memory data access register
	union {
		uint8_t mCH367Data8Sta;	   // F4H D7-D0 port status register
		uint32_t mCH367SData32Sta; // F4H D31-D0 port status register
	};
	uint8_t mCH367Status;	 // F8H Miscellaneous control and status register
	uint8_t mCH367IO_RESV3;	 // F9H
	uint8_t mCH367Speed;	 // FAH Speed control register
	uint8_t mCH367PDataCtrl; // FBH Passive parallel interface control register
	uint8_t mCH367IoTime;	 // FCH Hardware loop count register
	uint8_t mCH367SPICtrl;	 // FDH SPI control register
	uint8_t mCH367SPIData;	 // FEH SPI data register
	uint8_t mCH367IO_RESV4;	 // FFH
} mCH367_IO_REG, *mPCH367_IO_REG;

typedef struct _CH368_MEM_REG {	       // CH367 Memory space
	uint8_t mCH368MemPort[0x8000]; // 0000H-7FFFH, 32768 bytes in total
} mCH368_MEM_REG, *mPCH368_MEM_REG;

#define MAX(a, b)	   ((a) > (b) ? (a) : (b))
#define mMAX_BUFFER_LENGTH MAX(sizeof(mCH367_IO_REG), sizeof(mCH368_MEM_REG))

/**
 * ch36x_open - open ch36x device
 * @devname: the device name to open
 *
 * The function return the new file descriptor, or -1 if an error occurred
 */
extern int ch36x_open(const char *devname);
/**
 * ch36x_close - close ch36x device
 * @fd: the device handle
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_close(int fd);

/**
 * ch36x_get_chiptype - get chip model
 * @fd: file descriptor of ch36x device
 * @chiptype: pointer to chiptype
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_get_chiptype(int fd, enum CHIP_TYPE *chiptype);

/**
 * ch36x_get_version - get driver version
 * @fd: file descriptor of ch36x device
 * @version: pointer to version string
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_get_version(int fd, char *version);

/**
 * ch36x_get_irq - get irq number
 * @fd: file descriptor of ch36x device
 * @irq: pointer to irq number
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_get_irq(int fd, int *irq);

/**
 * ch36x_get_ioaddr - get io base address of ch36x
 * @fd: file descriptor of ch36x device
 * @ioaddr: pointer to io base address
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_get_ioaddr(int fd, void *ioaddr);

/**
 * ch36x_get_memaddr - get io memory address of ch36x
 * @fd: file descriptor of ch36x device
 * @memaddr: pointer to memory base address
 *
 * The function return 0 if success, others if fail.
 */

extern int ch36x_get_memaddr(int fd, void *memaddr);

/**
 * ch36x_read_config_byte - read one byte from config space
 * @fd: file descriptor of ch36x device
 * @offset: config space register offset
 * @obyte: pointer to read byte
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_config_byte(int fd, uint8_t offset, uint8_t *obyte);

/**
 * ch36x_read_config_word - read one word from config space
 * @fd: file descriptor of ch36x device
 * @offset: config space register offset
 * @oword: pointer to read word
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_config_word(int fd, uint8_t offset, uint16_t *oword);

/**
 * ch36x_read_config_dword - read one dword from config space
 * @fd: file descriptor of ch36x device
 * @offset: config space register offset
 * @oword: pointer to read dword
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_config_dword(int fd, uint8_t offset, uint32_t *odword);

/**
 * ch36x_write_config_byte - write one byte to config space
 * @fd: file descriptor of ch36x device
 * @offset: config space register offset
 * @ibyte: byte to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_config_byte(int fd, uint8_t offset, uint8_t ibyte);

/**
 * ch36x_write_config_word - write one word to config space
 * @fd: file descriptor of ch36x device
 * @offset: config space register offset
 * @iword: word to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_config_word(int fd, uint8_t offset, uint16_t iword);

/**
 * ch36x_write_config_dword - write one dword to config space
 * @fd: file descriptor of ch36x device
 * @offset: config space register offset
 * @dword: dword to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_config_dword(int fd, uint8_t offset, uint32_t idword);

/**
 * ch36x_read_io_byte - read one byte from io space
 * @fd: file descriptor of ch36x device
 * @offset: io space register offset
 * @obyte: pointer to read byte
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_io_byte(int fd, uint8_t offset, uint8_t *obyte);

/**
 * ch36x_read_io_word - read one byte from io word
 * @fd: file descriptor of ch36x device
 * @offset: io space register offset
 * @oword: pointer to read word
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_io_word(int fd, uint8_t offset, uint16_t *oword);

/**
 * ch36x_read_io_dword - read one dword from io space
 * @fd: file descriptor of ch36x device
 * @offset: io space register offset
 * @odword: pointer to read dword
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_io_dword(int fd, uint8_t offset, uint32_t *odword);

/**
 * ch36x_write_io_byte - write one byte to io space
 * @fd: file descriptor of ch36x device
 * @offset: io space register offset
 * @ibyte: byte to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_io_byte(int fd, uint8_t offset, uint8_t ibyte);

/**
 * ch36x_write_io_word - write one word to io space
 * @fd: file descriptor of ch36x device
 * @offset: io space register offset
 * @iword: word to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_io_word(int fd, uint8_t offset, uint16_t iword);

/**
 * ch36x_write_io_dword - write one dword to io space
 * @fd: file descriptor of ch36x device
 * @offset: io space register offset
 * @idword: dword to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_io_dword(int fd, uint8_t offset, uint32_t idword);

/**
 * ch36x_read_mem_byte - read one byte from memory space
 * @fd: file descriptor of ch36x device
 * @offset: memory space address offset
 * @obyte: pointer to read byte
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_mem_byte(int fd, uint16_t offset, uint8_t *obyte);

/**
 * ch36x_read_mem_word - read one word from memory space
 * @fd: file descriptor of ch36x device
 * @offset: memory space address offset
 * @oword: pointer to read word
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_mem_word(int fd, uint16_t offset, uint16_t *oword);

/**
 * ch36x_read_mem_dword - read one dword from memory space
 * @fd: file descriptor of ch36x device
 * @offset: memory space address offset
 * @odword: pointer to read dword
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_mem_dword(int fd, uint16_t offset, uint32_t *odword);

/**
 * ch36x_write_mem_byte - write one byte to mem space
 * @fd: file descriptor of ch36x device
 * @offset: memory space address offset
 * @ibyte: byte to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_mem_byte(int fd, uint16_t offset, uint8_t ibyte);

/**
 * ch36x_write_mem_word - write one word to mem space
 * @fd: file descriptor of ch36x device
 * @offset: memory space address offset
 * @iword: word to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_mem_word(int fd, uint16_t offset, uint16_t iword);

/**
 * ch36x_write_mem_dword - write one dword to mem space
 * @fd: file descriptor of ch36x device
 * @offset: memory space address offset
 * @idword: dword to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_mem_dword(int fd, uint16_t offset, uint32_t idword);

/**
 * ch36x_read_mem_block - read bytes from mem space
 * @fd: file descriptor of ch36x device
 * @type: SIZE_BYTE: 8-bit read, SIZE_DWORD: 32-bit read
 * @offset: memory space address offset
 * @obuffer: pointer to read buffer
 * @len: length to read
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_read_mem_block(int fd, uint8_t type, uint16_t offset, uint8_t *obuffer, uint32_t len);

/**
 * ch36x_write_mem_block - write bytes to mem space
 * @fd: file descriptor of ch36x device
 * @type: SIZE_BYTE: 8-bit write, SIZE_DWORD: 32-bit write
 * @offset: memory space address offset
 * @ibuffer: pointer to write buffer
 * @len: length to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_write_mem_block(int fd, uint8_t type, uint16_t offset, uint8_t *ibuffer, uint32_t len);

/**
 * ch36x_enable_isr - enable ch36x interrupt
 * @fd: file descriptor of ch36x device
 * @mode: interrupt mode
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_enable_isr(int fd, enum INTMODE mode);

/**
 * ch36x_disable_isr - disable ch36x interrupt
 * @fd: file descriptor of ch36x device
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_disable_isr(int fd);

/**
 * ch36x_set_int_routine - set interrupt handler
 * @fd: file descriptor of ch36x device
 * @isr_handler: handler to call when interrupt occurs
 *
 */
extern void ch36x_set_int_routine(int fd, void *isr_handler);

/**
 * ch36x_set_stream - set spi mode
 * @fd: file descriptor of ch36x device
 * @mode: bit0 on SPI Freq, 0->31.3MHz, 1->15.6MHz
 * 		  bit1 on SPI I/O Pinout, 0->SPI3(SCS/SCL/SDX), 1->SPI4(SCS/SCL/SDX/SDI)
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_set_stream(int fd, uint8_t mode);

/**
 * ch36x_stream_spi - spi transfer
 * @fd: file descriptor of ch36x device
 * @ibuffer: spi buffer to write
 * @len: length to xfer
 * @obuffer: pointer to read buffer
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_stream_spi(int fd, uint8_t *ibuffer, uint32_t ilen, uint8_t *obuffer, uint32_t olen);

/**
 * ch36x_flash_lock - lock/unlock spi flash
 * @fd: file descriptor of ch36x device
 * @lock: lock flag, 1 on lock, 0 on unlock
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_flash_lock(int fd, uint8_t lock);

/**
 * ch36x_flash_erase - erase spi flash
 * @fd: file descriptor of ch36x device
 * @addr: spi flash address to erase
 * @ilen: length to erase
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_flash_erase(int fd, uint32_t addr, uint32_t ilen);

/**
 * ch36x_flash_read - read spi flash
 * @fd: file descriptor of ch36x device
 * @addr: spi flash address to read
 * @obuffer: pointer to read buffer
 * @olen: length to xfer
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_flash_read(int fd, uint32_t addr, uint8_t *obuffer, uint32_t olen);

/**
 * ch36x_flash_write - write spi flash
 * @fd: file descriptor of ch36x device
 * @addr: spi flash address to write
 * @ibuffer: pointer to write buffer
 * @ilen: length to xfer
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_flash_write(int fd, uint32_t addr, uint8_t *ibuffer, uint32_t ilen);

/**
 * ch36x_i2c_write - write i2c data
 * @fd: file descriptor of ch36x device
 * @addr: i2c device address(low 7 bits specified)
 * @reg: i2c data unit address
 * @ibuffer: data to write
 * @ilen: pointer to length to write
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_i2c_write(int fd, uint8_t addr, uint8_t reg, uint8_t *ibuffer, uint32_t ilen);

/**
 * ch36x_i2c_read - read i2c data
 * @fd: file descriptor of ch36x device
 * @addr: i2c device address(low 7 bits specified)
 * @reg: i2c data unit address
 * @obuffer: pointer to read data
 * @olen: pointer to length to read
 *
 * The function return 0 if success, others if fail.
 */
extern int ch36x_i2c_read(int fd, uint8_t addr, uint8_t reg, uint8_t *obuffer, uint32_t olen);

#endif
