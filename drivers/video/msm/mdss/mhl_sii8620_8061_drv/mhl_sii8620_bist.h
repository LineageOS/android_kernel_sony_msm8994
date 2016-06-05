/* vendor/semc/hardware/mhl/mhl_sii8620_8061_drv/mhl_sii8620_bist.h
 *
 * Copyright (C) 2014 Sony Mobile Communications inc.
 * Copyright (C) 2014 Silicon Image Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#ifndef MHL_SII8620_BIST_H_
#define MHL_SII8620_BIST_H_

/* init/exit */
#ifdef MHL_BIST
void mhl_bist_initilize(struct device *pdev);
void mhl_bist_release(void);
#else
void mhl_bist_initilize(struct device *pdev){}
void mhl_bist_release(void){}
#endif

#endif /* MHL_SII8620_BIST_H_ */
