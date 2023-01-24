/*
 * Copyright 2018 NXP
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY NXP "AS IS" AND ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NXP OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
/* ###################################################################
**     Filename    : main.c
**     Project     : cse_keyconfig_mpc5777c
**     Processor   : MPC5777C_416
**     Version     : Driver 01.00
**     Compiler    : GNU C Compiler
**     Abstract    :
**         Main module.
**         This module contains user's application code.
**     Settings    :
**     Contents    :
**         No public methods
**
** ###################################################################*/
/*!
** @file main.c
** @version 01.00
** @brief
**         Main module.
**         This module contains user's application code.
*/         
/*!
**  @addtogroup main_module main module documentation
**  @{
*/         
/* MODULE main */
#include "Cpu.h"
#include "clockMan1.h"
#include "cse1.h"
#include "pin_mux.h"
volatile int exit_code = 0;
/* User includes (#include below this line is not maintained by Processor Expert) */
#include <stdint.h>
#include <stdbool.h>
#include "cse_utils.h"
#define GPIO_PORT      PTC
#define LED_1          21U
#define LED_2          22U
/* Set this macro-definition to 1 if you want to reset all the keys */
#define ERASE_ALL_KEYS	0
/*! 
  \brief The main function for the project.
  \details The startup initialization sequence is the following:
 * - startup asm routine
 * - main()
*/
int main(void)
{
  /* Write your local variable definition here */
  /*** Processor Expert internal initialization. DON'T REMOVE THIS CODE!!! ***/
  #ifdef PEX_RTOS_INIT
    PEX_RTOS_INIT();                   /* Initialization of the selected RTOS. Macro is defined by the RTOS component. */
  #endif
  /*** End of Processor Expert internal initialization.                    ***/
  /* Write your code here */
  bool keyLoaded;
  uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  /* Initialize and configure clocks
   * 	-	see clock manager component for details
   */
  CLOCK_SYS_Init(g_clockManConfigsArr, CLOCK_MANAGER_CONFIG_CNT,
						g_clockManCallbacksArr, CLOCK_MANAGER_CALLBACK_CNT);
  CLOCK_SYS_UpdateConfiguration(0U, CLOCK_MANAGER_POLICY_FORCIBLE);
  /* Initialize pins
   *	-	See PinSettings component for more info
   */
  PINS_DRV_Init(NUM_OF_CONFIGURED_PINS, g_pin_mux_InitConfigArr);
  /* Set Output value of the LEDs */
  PINS_DRV_SetPins(GPIO_PORT, (1 << LED_1) | (1 << LED_2));
  /* Initialize CSE driver */
  CSE_DRV_Init(&cse1_State);
  /* Load the MASTER_ECU key with a known value, which will be used as Authorization
   * key (a secret key known by the application in order to configure other user keys) */
  setAuthKey();
  /* Load the selected key */
  /* First load => counter == 1 */
  keyLoaded = loadKey(CSE_KEY_1, key, 1);
  if (keyLoaded)
  {
      /* Test an encryption using the loaded key.
       *
       * key        = 000102030405060708090a0b0c0d0e0f
       * plaintext  = 00112233445566778899aabbccddeeff
       * ciphertext = 69c4e0d86a7b0430d8cdb78070b4c55a
       *
       * The values are extracted from the SHE Spec 1.1 test vectors.
       */
      uint8_t i;
      status_t stat;
      bool encryptionOk = true;
      uint8_t cipherText[16];
      uint8_t plainText[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
      uint8_t expectedCipherText[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04,
        0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
      stat = CSE_DRV_EncryptECB(CSE_KEY_1, plainText, 16U, cipherText, 1U);
      if (stat == STATUS_SUCCESS)
      {
          /* Check if the cipher text is the one expected */
          for (i = 0; i < 16; i++)
          {
              if (cipherText[i] != expectedCipherText[i])
              {
                  encryptionOk = false;
                  break;
              }
          }
      }
      if (encryptionOk)
      {
          PINS_DRV_ClearPins(GPIO_PORT, 1 << LED_2);
      }
  }
  else
  {
	  PINS_DRV_ClearPins(GPIO_PORT, 1 << LED_1);
  }
#if ERASE_ALL_KEYS
  if (eraseKeys())
  {
	  PINS_DRV_ClearPins(GPIO_PORT, 1 << LED_1);
	  PINS_DRV_ClearPins(GPIO_PORT, 1 << LED_2);
  }
#endif
  /*** Don't write any code pass this line, or it will be deleted during code generation. ***/
  /*** RTOS startup code. Macro PEX_RTOS_START is defined by the RTOS component. DON'T MODIFY THIS CODE!!! ***/
  #ifdef PEX_RTOS_START
    PEX_RTOS_START();                  /* Startup of the selected RTOS. Macro is defined by the RTOS component. */
  #endif
  /*** End of RTOS startup code.  ***/
  /*** Processor Expert end of main routine. DON'T MODIFY THIS CODE!!! ***/
  for(;;) {
    if(exit_code != 0) {
      break;
    }
  }
  return exit_code;
  /*** Processor Expert end of main routine. DON'T WRITE CODE BELOW!!! ***/
} /*** End of main routine. DO NOT MODIFY THIS TEXT!!! ***/
/* END main */
/*!
** @}
*/
/*
** ###################################################################
**
**     This file was created by Processor Expert 10.1 [05.21]
**     for the NXP S32R series of microcontrollers.
**
** ###################################################################
*/
