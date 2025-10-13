#line 145 "bits.c"
int bitXor(int x, int y)
{
  int p1=  x & ~y;
  int p2=  ~x & y;
  return ~(~p1 & ~p2);
}
#line 157
int tmin(void)
{
  return 1 << 31;
}
#line 169
int isTmax(int x)
{
  int pls=  x + 1;
  int nonzero=  !!pls;
  int neg=  ~pls + 1;
  int negeqal=  !(neg ^ pls);
  return nonzero & negeqal;
}
#line 185
int allOddBits(int x)
{
  int mask=  0xAA;
  int oddBits;
  mask =( mask << 8) | mask;
  mask =( mask << 16) | mask;
  oddBits = x & mask;
  return !(oddBits ^ mask);
}
#line 201
int negate(int x)
{
  return ~x + 1;
}
#line 215
int isAsciiDigit(int x)
{
  int x_l=  x & 0xF;
  int x_h=  x >> 4;
  int hok=  !(x_h ^ 0x3);
  int exp=  0x9 + ~x_l + 1;
  int lok=  !(exp >> 31);
  return hok & lok;
}
#line 231
int conditional(int x, int y, int z)
{
  int val=  !!x;

  int mask=(  val << 31) >> 31;
  return (mask & y) +( ~mask & z);
}
#line 245
int isLessOrEqual(int x, int y)
{
  int sx=(  x >> 31) & 0x1;
  int sy=(  y >> 31) & 0x1;
  int r=  y + ~x + 1;
  int sr=(  r >> 31) & 0x1;
  int validr=  !(sx ^ sy) & !sr;
  return (sx & !sy) | validr;
}
#line 263
int logicalNeg(int x)
{
  return 2;
}
#line 279
int howManyBits(int x)
{
  return 0;
}
#line 295
unsigned floatScale2(unsigned uf)
{
  return 2;
}
#line 311
int floatFloat2Int(unsigned uf)
{
  return 2;
}
#line 328
unsigned floatPower2(int x)
{
  return 2;
}
