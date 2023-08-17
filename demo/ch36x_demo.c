/*
 * ch365/ch367/ch368 PCI/PCIE application demo
 *
 * Copyright (C) 2023 Nanjing Qinheng Microelectronics Co., Ltd.
 * Web:      http://wch.cn
 * Author:   WCH <tech@wch.cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Cross-compile with cross-gcc -I /path/to/cross-kernel/include
 *
 * Update Log:
 * V1.0 - initial version
 * V1.1 - call new APIs with ch36x_lib
 * V1.2 - call SPI and I2C APIs with ch36x_lib
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "ch36x_lib.h"

static const char *device = "/dev/ch36xpci0";

static void ch36x_demo_io_operate(int fd)
{
	int ret;
	char c;
	uint32_t ibyte;
	uint32_t offset;
	uint8_t obyte;

	printf("\n---------- IO read write test ----------\n");
	while (1) {
		printf("press w to write one byte, r to read one byte, q for quit.\n");
		scanf("%c", &c);
		getchar();
		if (c == 'q')
			break;
		switch (c) {
		case 'w':
			printf("input offset of io:\n");
			scanf("%x", &offset);
			getchar();
			printf("input write value:\n");
			scanf("%x", &ibyte);
			getchar();
			ret = ch36x_write_io_byte(fd, (uint8_t)offset, (uint8_t)ibyte);
			if (ret != 0)
				printf("io write fail.\n");
			break;
		case 'r':
			printf("input offset of io:\n");
			scanf("%x", &offset);
			getchar();
			ret = ch36x_read_io_byte(fd, (uint8_t)offset, &obyte);
			if (ret != 0)
				printf("io read fail.\n");
			printf("read byte: 0x%2x\n", obyte);
			break;
		default:
			break;
		}
	}
}

static void ch36x_demo_mem_operate(int fd)
{
	int ret;
	char c;
	uint32_t ibyte;
	uint32_t offset;
	uint8_t obyte;

	printf("\n---------- Memory read write test ----------\n");
	while (1) {
		printf("press w to write one byte, r to read one byte, q for quit.\n");
		scanf("%c", &c);
		getchar();
		if (c == 'q')
			break;
		switch (c) {
		case 'w':
			printf("input offset of mem:\n");
			scanf("%x", &offset);
			getchar();
			printf("input write value:\n");
			scanf("%x", &ibyte);
			getchar();
			ret = ch36x_write_mem_byte(fd, (uint16_t)offset, (uint8_t)ibyte);
			if (ret != 0)
				printf("memory write fail.\n");
			break;
		case 'r':
			printf("input offset of mem:\n");
			scanf("%x", &offset);
			getchar();
			ret = ch36x_read_mem_byte(fd, (uint16_t)offset, &obyte);
			if (ret != 0)
				printf("memory read fail.\n");
			printf("read byte: 0x%2x\n", obyte);
			break;
		default:
			break;
		}
	}
}

static void ch36x_demo_config_operate(int fd)
{
	int ret;
	char c;
	uint32_t ibyte;
	uint32_t offset;
	uint8_t obyte;

	printf("\n---------- Config space read write test ----------\n");
	while (1) {
		printf("press w to write one byte, r to read one byte, q for quit.\n");
		scanf("%c", &c);
		getchar();
		if (c == 'q')
			break;
		switch (c) {
		case 'w':
			printf("input offset of config space:\n");
			scanf("%x", &offset);
			getchar();
			printf("input write value:\n");
			scanf("%x", &ibyte);
			getchar();
			ret = ch36x_write_config_byte(fd, (uint8_t)offset, (uint8_t)ibyte);
			if (ret != 0)
				printf("config space write fail.\n");
			break;
		case 'r':
			printf("input offset of config space:\n");
			scanf("%x", &offset);
			getchar();
			ret = ch36x_read_config_byte(fd, (uint8_t)offset, &obyte);
			if (ret != 0)
				printf("config space read fail.\n");
			printf("read byte: 0x%2x\n", obyte);
			break;
		default:
			break;
		}
	}
}

static void ch36x_dmeo_isr_handler(int signo)
{
	static int int_times = 0;

	printf("ch36x interrupt times: %d\n", int_times++);
}

static void ch36x_demo_isr_enable(int fd)
{
	int ret;
	enum INTMODE mode = INT_FALLING;

	ret = ch36x_enable_isr(fd, mode);
	if (ret != 0) {
		printf("ch36x_enable_isr failed.\n");
		return;
	}
	ch36x_set_int_routine(fd, ch36x_dmeo_isr_handler);
}

static void ch36x_demo_isr_disable(int fd)
{
	int ret;

	ret = ch36x_disable_isr(fd);
	if (ret != 0) {
		printf("ch36x_disable_isr failed.\n");
		return;
	}
	ch36x_set_int_routine(fd, NULL);
}

static void ch36x_demo_spi_operate(int fd)
{
	/* bit0 of mode on SPI Freq, 0->31.3MHz, 1->15.6MHz */
	/* bit1 of mode on SPI I/O Pinout, 0->SPI3(SCS/SCL/SDX), 1->SPI4(SCS/SCL/SDX/SDI) */
	uint8_t mode = 0x01;
	int ret;
	uint32_t ilen, olen;
	uint8_t ibuffer[1024];
	uint8_t obuffer[1024];
	int i;

	printf("\n---------- SPI read write test ----------\n");
	ret = ch36x_set_stream(fd, mode);
	if (ret) {
		printf("set stream error.\n");
		return;
	}
	printf("input write length:\n");
	scanf("%d", &ilen);
	getchar();
	printf("input read length:\n");
	scanf("%d", &olen);
	getchar();
	memset(ibuffer, 0x55, sizeof(ibuffer));
	ret = ch36x_stream_spi(fd, ibuffer, ilen, obuffer, olen);
	if (ret != 0) {
		printf("spi transfer fail.\n");
		return;
	}
	printf("\n---------- read buffer ----------\n");
	for (i = 0; i < olen; i++) {
		printf("\tobuffer[%d]: 0x%2x\n", i, obuffer[i]);
	}
	printf("\n");
}

static void ch36x_demo_flash_operate(int fd)
{
	/* bit0 of mode on SPI Freq, 0->31.3MHz, 1->15.6MHz */
	/* bit1 of mode on SPI I/O Pinout, 0->SPI3(SCS/SCL/SDX), 1->SPI4(SCS/SCL/SDX/SDI) */
	uint8_t mode = 0x01;
	int ret;
	uint32_t olen;
	uint32_t addr;
	uint8_t ibuffer[1024];
	uint8_t obuffer[1024];
	int i;

	printf("\n---------- flash read write test ----------\n");
	ret = ch36x_set_stream(fd, mode);
	if (ret) {
		printf("set stream error.\n");
		return;
	}
	printf("input flash addr:\n");
	scanf("%d", &addr);
	getchar();
	printf("please input string to write:\n");
	scanf("%s", ibuffer);
	getchar();
	ret = ch36x_flash_erase(fd, addr, strlen(ibuffer));
	if (ret != 0) {
		printf("spi flash erase fail.\n");
		return;
	} else {
		printf("spi flash addr [0x%x - 0x%x] erased successfully.\n", addr, addr + (uint32_t)strlen(ibuffer));
	}
	ret = ch36x_flash_write(fd, addr, ibuffer, strlen(ibuffer));
	if (ret != 0) {
		printf("spi flash write fail.\n");
		return;
	} else {
		printf("spi flash addr [0x%x - 0x%x] wrote successfully.\n", addr, addr + (uint32_t)strlen(ibuffer));
	}
	printf("input read length:\n");
	scanf("%d", &olen);
	getchar();
	printf("\n---------- read spi flash from addr %d ----------\n", addr);
	ret = ch36x_flash_read(fd, addr, obuffer, olen);
	if (ret != 0) {
		printf("spi flash read fail.\n");
		return;
	}
	for (i = 0; i < olen; i++) {
		printf("\tobuffer[%d]: 0x%2x\n", i, obuffer[i]);
	}
	printf("\n");
}

static void ch36x_demo_eeprom_operate(int fd)
{
	int ret;
	uint32_t olen;
	uint32_t addr;
	uint32_t reg;
	uint8_t ibuffer[1024];
	uint8_t obuffer[1024];
	int i;

	printf("\n---------- eeprom read write test ----------\n");
	printf("input device addr:\n");
	scanf("%x", &addr);
	getchar();
	printf("input data unit addr:\n");
	scanf("%x", &reg);
	getchar();
	printf("please input string to write:\n");
	scanf("%s", ibuffer);
	getchar();
	ret = ch36x_i2c_write(fd, (uint8_t)addr, (uint8_t)reg, ibuffer, (uint32_t)strlen(ibuffer));
	if (ret != 0) {
		printf("eeprom write fail.\n");
		return;
	} else {
		printf("eeprom data addr [0x%x - 0x%x] wrote successfully.\n", reg, reg + (uint32_t)strlen(ibuffer));
	}
	printf("input read length:\n");
	scanf("%d", &olen);
	getchar();
	printf("\n---------- read eeprom from addr %d ----------\n", reg);
	ret = ch36x_i2c_read(fd, (uint8_t)addr, (uint8_t)reg, obuffer, olen);
	if (ret != 0) {
		printf("eeprom read fail.\n");
		return;
	}
	for (i = 0; i < olen; i++) {
		printf("\tobuffer[%d]: 0x%2x\n", i, obuffer[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	int fd;
	int ret;
	char c;
	enum CHIP_TYPE chiptype;
	unsigned long iobase;
	unsigned long membase;
	int irq;

	fd = ch36x_open(device);
	if (fd < 0) {
		printf("ch36x_open error.\n");
		goto exit;
	}

	ret = ch36x_get_chiptype(fd, &chiptype);
	if (ret != 0) {
		printf("ch36x_get_chiptype error.\n");
		goto exit;
	}
	switch (chiptype) {
	case CHIP_CH365:
		printf("current chip model: CH365.\n");
		break;
	case CHIP_CH367:
		printf("current chip model: CH367.\n");
		break;
	case CHIP_CH368:
		printf("current chip model: CH368.\n");
		break;
	}

	ret = ch36x_get_irq(fd, &irq);
	if (ret != 0) {
		printf("ch36x_get_irq error.\n");
		goto exit;
	}
	printf("irq number:%d\n", irq);

	ret = ch36x_get_ioaddr(fd, &iobase);
	if (ret != 0) {
		printf("ch36x_get_ioaddr error.\n");
		goto exit;
	}
	printf("iobase:%lx\n", iobase);

	if (chiptype == CHIP_CH368) {
		ret = ch36x_get_memaddr(fd, &membase);
		if (ret != 0) {
			printf("ch36x_get_memaddr error.\n");
			goto exit;
		}
		printf("membase:%lx\n", membase);
	}

	while (1) {
		printf("press c to operate config space, m to operate memory space, "
		       "i to operate io space, e to enable interrupt, "
		       "d to disable interrpt, s to operate spi, "
		       "f to operate spi flash, p to operate eeprom, "
		       "q for quit.\n");
		scanf("%c", &c);
		getchar();
		if (c == 'q')
			break;
		switch (c) {
		case 'i':
			ch36x_demo_io_operate(fd);
			break;
		case 'm':
			if (chiptype == CHIP_CH368)
				ch36x_demo_mem_operate(fd);
			else
				printf("chip not support.\n");
			break;
		case 'c':
			ch36x_demo_config_operate(fd);
			break;
		case 'e':
			ch36x_demo_isr_enable(fd);
			break;
		case 'd':
			ch36x_demo_isr_disable(fd);
			break;
		case 's':
			ch36x_demo_spi_operate(fd);
			break;
		case 'f':
			ch36x_demo_flash_operate(fd);
			break;
		case 'p':
			ch36x_demo_eeprom_operate(fd);
		default:
			break;
		}
	}

	ret = ch36x_close(fd);
	if (ret != 0) {
		printf("ch36x_close error.\n");
		goto exit;
	}

exit:
	return ret;
}
