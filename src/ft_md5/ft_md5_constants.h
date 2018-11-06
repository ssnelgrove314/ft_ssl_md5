#ifndef FT_MD5_CONSTANTS
# define FT_MD5_CONSTANTS

# include <stdint.h>

enum e_fghi {
	MD5_F_FF,
	MD5_G_GG,
	MD5_H_HH,
	MD5_I_II,
};

typedef struct	s_md5_round
{
	char		fghi;
	short		sub_block;
	short		step;
	uint32_t	signed_constant;
}				t_md5_round;

unsigned char g_md5_padding[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

t_md5_round		g_md5_rounds[4][16] = {
	{
		{MD5_F_FF, 0, 7, 0xd76aa478},
		{MD5_F_FF, 1, 12, 0xe8c7b756},
		{MD5_F_FF, 2, 17, 0x242070db},
		{MD5_F_FF, 3, 22, 0xc1bdceee},
		{MD5_F_FF, 4, 7, 0xf57c0faf},
		{MD5_F_FF, 5, 12, 0x4787c62a},
		{MD5_F_FF, 6, 17, 0xa8304613},
		{MD5_F_FF, 7, 22, 0xfd469501},
		{MD5_F_FF, 8, 7, 0x698098d8},
		{MD5_F_FF, 9, 12, 0x8b44f7af},
		{MD5_F_FF, 10, 17, 0xffff5bb1},
		{MD5_F_FF, 11, 22, 0x895cd7be},
		{MD5_F_FF, 12, 7, 0x6b901122},
		{MD5_F_FF, 13, 12, 0xfd987193},
		{MD5_F_FF, 14, 17, 0xa679438e},
		{MD5_F_FF, 15, 22, 0x49b40821}
	},
	{
		{MD5_G_GG, 1, 5, 0xf61e2562},
		{MD5_G_GG, 6, 9, 0xc040b340},
		{MD5_G_GG, 11, 14, 0x265e5a51},
		{MD5_G_GG, 0, 20, 0xe9b6c7aa},
		{MD5_G_GG, 5, 5, 0xd62f105d},
		{MD5_G_GG, 10, 9, 0x02441453},
		{MD5_G_GG, 15, 14, 0xd8a1e681},
		{MD5_G_GG, 4, 20, 0xe7d3fbc8},
		{MD5_G_GG, 9, 5, 0x21e1cde6},
		{MD5_G_GG, 14, 9, 0xc33707d6},
		{MD5_G_GG, 3, 14, 0xf4d50d87},
		{MD5_G_GG, 8, 20, 0x455a14ed},
		{MD5_G_GG, 13, 5, 0xa9e3e905},
		{MD5_G_GG, 2, 9, 0xfcefa3f8},
		{MD5_G_GG, 7, 14, 0x676f02d9},
		{MD5_G_GG, 12, 20, 0x8d2a4c8a},
	},
	{
		{MD5_H_HH, 5, 4, 0xfffa3942},
		{MD5_H_HH, 8, 11, 0x8771f681},
		{MD5_H_HH, 11, 16, 0x6d9d6122},
		{MD5_H_HH, 14, 23, 0xfde5380c},
		{MD5_H_HH, 1, 4, 0xa4beea44},
		{MD5_H_HH, 4, 11, 0x4bdecfa9},
		{MD5_H_HH, 7, 16, 0xf6bb4b60},
		{MD5_H_HH, 10, 23, 0xbebfbc70},
		{MD5_H_HH, 13, 4, 0x289b7ec6},
		{MD5_H_HH, 0, 11, 0xeaa127fa},
		{MD5_H_HH, 3, 16, 0xd4ef3085},
		{MD5_H_HH, 6, 23, 0x04881d05},
		{MD5_H_HH, 9, 4, 0xd9d4d039},
		{MD5_H_HH, 12, 11, 0xe6db99e5},
		{MD5_H_HH, 15, 16, 0x1fa27cf8},
		{MD5_H_HH, 2, 23, 0xc4ac5665}
	},
	{
		{MD5_I_II, 0, 6, 0xf4292244},
		{MD5_I_II, 7, 10, 0x432aff97},
		{MD5_I_II, 14, 15, 0xab9423a7},
		{MD5_I_II, 5, 21, 0xfc93a039},
		{MD5_I_II, 12, 6, 0x655b59c3},
		{MD5_I_II, 3, 10, 0x8f0ccc92},
		{MD5_I_II, 10, 15, 0xffeff47d},
		{MD5_I_II, 1, 21, 0x85845dd1},
		{MD5_I_II, 8, 6, 0x6fa87e4f},
		{MD5_I_II, 15, 10, 0xfe2ce6e0},
		{MD5_I_II, 6, 15, 0xa3014314},
		{MD5_I_II, 13, 21, 0x4e0811a1},
		{MD5_I_II, 4, 6, 0xf7537e82},
		{MD5_I_II, 11, 10, 0xbd3af235},
		{MD5_I_II, 2, 15, 0x2ad7d2bb},
		{MD5_I_II, 9, 21, 0xeb86d391}
	}
};

#endif