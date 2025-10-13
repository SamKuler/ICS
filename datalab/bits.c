/*
 * CS:APP Data Lab
 *
 * Zeng Guan Yang
 * 2023012156
 *
 * bits.c - Source file with your solutions to the Lab.
 *          This is the file you will hand in to your instructor.
 *
 * WARNING: Do not include the <stdio.h> header; it confuses the dlc
 * compiler. You can still use printf for debugging without including
 * <stdio.h>, although you might get a compiler warning. In general,
 * it's not good practice to ignore compiler warnings, but in this
 * case it's OK.
 */

#if 0
/*
 * Instructions to Students:
 *
 * STEP 1: Read the following instructions carefully.
 */

You will provide your solution to the Data Lab by
editing the collection of functions in this source file.

INTEGER CODING RULES:
 
  Replace the "return" statement in each function with one
  or more lines of C code that implements the function. Your code 
  must conform to the following style:
 
  int Funct(arg1, arg2, ...) {
      /* brief description of how your implementation works */
      int var1 = Expr1;
      ...
      int varM = ExprM;

      varJ = ExprJ;
      ...
      varN = ExprN;
      return ExprR;
  }

  Each "Expr" is an expression using ONLY the following:
  1. Integer constants 0 through 255 (0xFF), inclusive. You are
      not allowed to use big constants such as 0xffffffff.
  2. Function arguments and local variables (no global variables).
  3. Unary integer operations ! ~
  4. Binary integer operations & ^ | + << >>
    
  Some of the problems restrict the set of allowed operators even further.
  Each "Expr" may consist of multiple operators. You are not restricted to
  one operator per line.

  You are expressly forbidden to:
  1. Use any control constructs such as if, do, while, for, switch, etc.
  2. Define or use any macros.
  3. Define any additional functions in this file.
  4. Call any functions.
  5. Use any other operations, such as &&, ||, -, or ?:
  6. Use any form of casting.
  7. Use any data type other than int.  This implies that you
     cannot use arrays, structs, or unions.

 
  You may assume that your machine:
  1. Uses 2s complement, 32-bit representations of integers.
  2. Performs right shifts arithmetically.
  3. Has unpredictable behavior when shifting if the shift amount
     is less than 0 or greater than 31.


EXAMPLES OF ACCEPTABLE CODING STYLE:
  /*
   * pow2plus1 - returns 2^x + 1, where 0 <= x <= 31
   */
  int pow2plus1(int x) {
     /* exploit ability of shifts to compute powers of 2 */
     return (1 << x) + 1;
  }

  /*
   * pow2plus4 - returns 2^x + 4, where 0 <= x <= 31
   */
  int pow2plus4(int x) {
     /* exploit ability of shifts to compute powers of 2 */
     int result = (1 << x);
     result += 4;
     return result;
  }

FLOATING POINT CODING RULES

For the problems that require you to implement floating-point operations,
the coding rules are less strict.  You are allowed to use looping and
conditional control.  You are allowed to use both ints and unsigneds.
You can use arbitrary integer and unsigned constants. You can use any arithmetic,
logical, or comparison operations on int or unsigned data.

You are expressly forbidden to:
  1. Define or use any macros.
  2. Define any additional functions in this file.
  3. Call any functions.
  4. Use any form of casting.
  5. Use any data type other than int or unsigned.  This means that you
     cannot use arrays, structs, or unions.
  6. Use any floating point data types, operations, or constants.


NOTES:
  1. Use the dlc (data lab checker) compiler (described in the handout) to 
     check the legality of your solutions.
  2. Each function has a maximum number of operations (integer, logical,
     or comparison) that you are allowed to use for your implementation
     of the function.  The max operator count is checked by dlc.
     Note that assignment ('=') is not counted; you may use as many of
     these as you want without penalty.
  3. Use the btest test harness to check your functions for correctness.
  4. Use the BDD checker to formally verify your functions
  5. The maximum number of ops for each function is given in the
     header comment for each function. If there are any inconsistencies 
     between the maximum ops in the writeup and in this file, consider
     this file the authoritative source.

/*
 * STEP 2: Modify the following functions according the coding rules.
 * 
 *   IMPORTANT. TO AVOID GRADING SURPRISES:
 *   1. Use the dlc compiler to check that your solutions conform
 *      to the coding rules.
 *   2. Use the BDD checker to formally verify that your solutions produce 
 *      the correct answers.
 */

#endif
// 1
/*
 * bitXor - x^y using only ~ and &
 *   Example: bitXor(4, 5) = 1
 *   Legal ops: ~ &
 *   Max ops: 14
 *   Rating: 1
 */
int bitXor(int x, int y)
{
  int p1 = x & ~y;
  int p2 = ~x & y;     // x ^ y = p1 | p2
  return ~(~p1 & ~p2); // actual p1 | p2
}
/*
 * tmin - return minimum two's complement integer
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 4
 *   Rating: 1
 */
int tmin(void)
{
  return 1 << 31; // 0x80000000
}
// 2
/*
 * isTmax - returns 1 if x is the maximum, two's complement number,
 *     and 0 otherwise
 *   Legal ops: ! ~ & ^ | +
 *   Max ops: 10
 *   Rating: 1
 */
int isTmax(int x)
{
  int pls = x + 1;
  int nonzero = !!pls;        // if 1, x != -1, 0 for x=-1
  int neg = ~pls + 1;         // neg = -pls = -(x+1)
  int negeqal = !(neg ^ pls); // (x+1)==-(x+1)
  return nonzero & negeqal;   // nonzero && -pls==pls
}
/*
 * allOddBits - return 1 if all odd-numbered bits in word set to 1
 *   where bits are numbered from 0 (least significant) to 31 (most significant)
 *   Examples allOddBits(0xFFFFFFFD) = 0, allOddBits(0xAAAAAAAA) = 1
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 2
 */
int allOddBits(int x)
{
  int mask = 0xAA;
  int oddBits;
  mask = (mask << 8) | mask;  // 0xAAAA
  mask = (mask << 16) | mask; // 0xAAAAAAAA
  oddBits = x & mask;         // get all odd bits of x
  return !(oddBits ^ mask);   // check whether odd bits are all 1.
}
/*
 * negate - return -x
 *   Example: negate(1) = -1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 5
 *   Rating: 2
 */
int negate(int x)
{
  return ~x + 1;
}
// 3
/*
 * isAsciiDigit - return 1 if 0x30 <= x <= 0x39 (ASCII codes for characters '0' to '9')
 *   Example: isAsciiDigit(0x35) = 1.
 *            isAsciiDigit(0x3a) = 0.
 *            isAsciiDigit(0x05) = 0.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 15
 *   Rating: 3
 */
int isAsciiDigit(int x)
{
  int x_l = x & 0xF;        // Lower 4 bits of x
  int x_h = x >> 4;         // Higher bits of x
  int hok = !(x_h ^ 0x3);   // Satisfy 0x3?
  int exp = 0x9 + ~x_l + 1; // 0x9 - x_l
  int lok = !(exp >> 31);   // 0x9 - x_l >= 0
  return hok & lok;
}
/*
 * conditional - same as x ? y : z
 *   Example: conditional(2,4,5) = 4
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 16
 *   Rating: 3
 */
int conditional(int x, int y, int z)
{
  int val = !!x; // get condition result
  // fill the mask with condition value
  int mask = (val << 31) >> 31;
  return (mask & y) + (~mask & z);
}
/*
 * isLessOrEqual - if x <= y  then return 1, else return 0
 *   Example: isLessOrEqual(4,5) = 1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 24
 *   Rating: 3
 */
int isLessOrEqual(int x, int y)
{
  int sx = (x >> 31) & 0x1; // Get the sign of x
  int sy = (y >> 31) & 0x1; // Get the sign of y
  int r = y + ~x + 1;
  int sr = (r >> 31) & 0x1;      // Get the sign of result
  int validr = !(sx ^ sy) & !sr; // when signs are the same, check r>=0
  return (sx & !sy) | validr;    // first indicates x<0 && y>=0
}
// 4
/*
 * logicalNeg - implement the ! operator, using all of
 *              the legal operators except !
 *   Examples: logicalNeg(3) = 0, logicalNeg(0) = 1
 *   Legal ops: ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 4
 */
int logicalNeg(int x)
{
  int neg = ~x + 1;        // neg = -x
  int y = x | neg;         // y = x|-x
  return ~(y >> 31) & 0x1; // ~sign(y) & 0x1, negate the sign.
}
/* howManyBits - return the minimum number of bits required to represent x in
 *             two's complement
 *  Examples: howManyBits(12) = 5
 *            howManyBits(298) = 10
 *            howManyBits(-5) = 4
 *            howManyBits(0)  = 1
 *            howManyBits(-1) = 1
 *            howManyBits(0x80000000) = 32
 *  Legal ops: ! ~ & ^ | + << >>
 *  Max ops: 90
 *  Rating: 4
 */
int howManyBits(int x)
{
  int s = x >> 31; // sign maskx
  int v = (s & ~x) | (~s & x);
  int _16bit, _8bit, _4bit, _2bit, _1bit;
  // 32 bit split
  _16bit = !!(v >> 16) << 4; // high 16bits. check if there's 1. turn the result to count.
  v = v >> _16bit;           // _16bit = 0 => highest 1 in lower 16bit;
                             // _16bit = 16 => highest 1 in higher 16bit, needs shift.
  // 16 bit split
  _8bit = !!(v >> 8) << 3; // check high 8 bits. store the count.
  v = v >> _8bit;          // similar operation
  // 8 bit split
  _4bit = !!(v >> 4) << 2;
  v = v >> _4bit;
  // 4 bit split
  _2bit = !!(v >> 2) << 1;
  v = v >> _2bit;
  // 2 bit split
  _1bit = !!(v >> 1);
  v = v >> _1bit; // needs to know v is in high bit or low bit.
  // adds up. v it self represent the 1bit result.
  return _16bit + _8bit + _4bit + _2bit + _1bit + v + 1;
}
// float
/*
 * floatScale2 - Return bit-level equivalent of expression 2*f for
 *   floating point argument f.
 *   Both the argument and result are passed as unsigned int's, but
 *   they are to be interpreted as the bit-level representation of
 *   single-precision floating point values.
 *   When argument is NaN, return argument
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
unsigned floatScale2(unsigned uf)
{
  unsigned sgn = uf & 0x80000000u;   // sign part
  unsigned exp = (uf >> 23) & 0xFFu; // exp part
  unsigned frac = uf & 0x7fffffu;    // frac part
  if (exp == 0)                      // denorm
  {
    frac = frac << 1;
    return sgn | frac;
  }
  if (exp == 0xffu) // NaN, infty
  {
    return uf;
  }
  exp = exp + 1;    // norm
  if (exp == 0xffu) // overflow
  {
    return sgn | (exp << 23); // no need for frac part.
  }
  return sgn | (exp << 23) | frac;
}
/*
 * floatFloat2Int - Return bit-level equivalent of expression (int) f
 *   for floating point argument f.
 *   Argument is passed as unsigned int, but
 *   it is to be interpreted as the bit-level representation of a
 *   single-precision floating point value.
 *   Anything out of range (including NaN and infinity) should return
 *   0x80000000u.
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
int floatFloat2Int(unsigned uf)
{
  unsigned sgn = uf & 0x80000000u;
  unsigned exp = (uf >> 23) & 0xFFu;
  unsigned frac = uf & 0x7fffffu;
  unsigned v;
  int E;
  if (exp == 255)
  {
    return 0x80000000u;
  }
  E = exp - 127; // actually, the same logic for norm & denorm
  if (E < 0)
  {
    return 0;
  }
  else if (E > 30) // out of range for norm
  {
    return 0x80000000u;
  }
  v = (1u << 23) | frac; // 1 for hidden bit
  if (E >= 23)
  {
    v = v << (E - 23);
  }
  else // 0<=E<23
  {
    v = v >> (23 - E);
  }
  if (sgn)
  {
    return -v;
  }
  else
  {
    return v;
  }
}
/*
 * floatPower2 - Return bit-level equivalent of the expression 2.0^x
 *   (2.0 raised to the power x) for any 32-bit integer x.
 *
 *   The unsigned value that is returned should have the identical bit
 *   representation as the single-precision floating-point number 2.0^x.
 *   If the result is too small to be represented as a denorm, return
 *   0. If too large, return +INF.
 *
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. Also if, while
 *   Max ops: 30
 *   Rating: 4
 */
unsigned floatPower2(int x)
{
  if (x >= 128) // too large
  {
    return 0x7f800000; // +INF
  }
  else if (x >= -126) // norm , frac = 0
  {
    unsigned exp = 127 + x;
    return exp << 23;
  }
  else if (x >= -149) // denorm, use frac to represent
  {
    return 1u << (x + 149);
  }
  else // too small to represent, return 0
  {
    return 0;
  }
}
