#include "iostream"
#include  "algorithm"
#include "cstring"
#include "math.h"
#include "cstdlib"

typedef unsigned int uint4;
typedef unsigned char uint1;

#define F(x, y, z) (((x) & (y)) | ((~x) & (z))) 
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

uint4 state[4] = {0x67452301, 0xefcdab89 , 0x98badcfe, 0x10325476};


//常量 uint4(abs(sin(i+1))*(2pow32))，算法要求
const uint4 con_var[]={
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
        0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,
        0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,
        0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,
        0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,
        0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,
        0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,
        0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
        0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,
        0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
        0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,
        0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};

//向左位移数,算法要求
const uint4 times[]={7,12,17,22,7,12,17,22,7,12,17,22,7,
        12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,
        15,21,6,10,15,21,6,10,15,21,6,10,15,21};
// const uint4 times[]={7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21};

// 64bit分组的下标
const uint4 subStrIndex[] = {
		0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
		1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
		5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
		0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
	};

// 补足位数使得使得补足之后的位数除以512余448，而且必须进行，算法要求这么做的，这里的padding就是要用来补足的char
uint1 padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* 因为md5要求处理的后的字符串的最后64位表示要加密的字符串的长度，而unsigned int为32bits，所以使用2个（2 * 32）unsigned int表示表示字符串
的长度，count[1]表示字符串长度的高位，count[0]表示字符串长度的低位
*/
uint4 count[2];

uint1 buffer[64];

/*将4字节的整数copy到字符形式的缓冲区中
output：用于输出的字符缓冲区
input：欲转换的四字节的整数形式的数组
len：output缓冲区的长度，要求是4的整数倍
*/
void encode(uint1 *output, uint4 *input, uint4 len) {
    uint4 i, j;
    for(i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (uint1)(input[i] & 0xff);
        output[j+1] = (uint1)((input[i] >> 8) & 0xff);
        output[j+2] = (uint1)((input[i] >> 16) & 0xff);
        output[j+3] = (uint1)((input[i] >> 24) & 0xff);
    }
}

/*与上面的函数正好相反，这一个把字符形式的缓冲区中的数据copy到4字节的整数中（即以整数形式保存）
output：保存转换出的整数
input：欲转换的字符缓冲区
len：输入的字符缓冲区的长度，要求是4的整数倍
*/
void decode(uint4 *output, uint1 *input, uint4 len) {
    uint4 i, j;
    for(i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint4)input[j]) | (((uint4)input[j+1]) << 8) |
                    (((uint4)input[j+2]) << 16) | (((uint4)input[j+3]) << 24);
}



uint4 rotate_left(uint4 number, uint4 rotate_times) {
	return (number << rotate_times) | (number >> (32 - rotate_times));
}
uint4 FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 sub_group, uint4 rotate_times, uint4 con_var) {
	return a = rotate_left(F(b, c, d) + a + con_var + sub_group, rotate_times) + b;
}
uint4 GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 sub_group, uint4 rotate_times, uint4 con_var) {
	return a = rotate_left(G(b, c, d) + a + con_var + sub_group, rotate_times) + b;
}
uint4 HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 sub_group, uint4 rotate_times, uint4 con_var) {
	return a = rotate_left(H(b, c, d) + a + con_var + sub_group, rotate_times) + b;
}
uint4 II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 sub_group, uint4 rotate_times, uint4 con_var) {
	return a = rotate_left(I(b, c, d) + a + con_var + sub_group, rotate_times) + b;
}

void transform(uint1 input[64]) {
	uint4 temp_result, a = state[0], b = state[1], c = state[2], d = state[3], groups[16];

	decode(groups, input, 64);

	for (uint4 i = 0; i < 64; i++) {
		// 进行加密操作
        if(i < 16) {
           temp_result = FF(a, b, c, d, groups[subStrIndex[i]], times[i], con_var[i]);
        } else if (i < 32) {
           temp_result = GG(a, b, c, d, groups[subStrIndex[i]], times[i], con_var[i]);
        } else if(i < 48) {
           temp_result = HH(a, b, c, d, groups[subStrIndex[i]], times[i], con_var[i]);
        } else {
           temp_result = II(a, b, c, d, groups[subStrIndex[i]], times[i], con_var[i]);
        }
        // 交换abcd的位置达到随机的目的
        a = d;
        d = c;
        c = b;
        b = temp_result;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// 这里是以64bit为单位来进行，先处理完第一个64位，然后再处理第二个64位,如此下去
void update(unsigned char * input, uint4 inputlen) {
	uint4 i, index, partlen;

	/*计算已有信息的bits长度的字节数的模64, 64bytes=512bits。
    用于判断已有信息加上当前传过来的信息的总长度能不能达到512bits，
    如果能够达到则对凑够的512bits进行一次处理*/
    index = (uint4)((count[0] >> 3) & 0x3F);

    /*更新已有信息的bits长度
	如果count[0] += ((uint4)inputlen << 3)) < ((uint4)inputlen << 3)表示溢出
	则count[1]++，在第二次和第三次的时候执行这个函数生效
    */
     if((count[0] += ((uint4)inputlen << 3)) < ((uint4)inputlen << 3))
        count[1]++;

    // inputlen传进来的是byte所以只需要右移29位不是32位，这里一个unsigned int够表示字符串的长度最长为2的64次方，超过的即将被忽略
    count[1] += ((uint4)inputlen >> 29);

    /*计算已有的字节数长度还差多少字节可以 凑成64的整倍数*/
    partlen = 64 - index;

    /*如果当前输入的字节数 大于 已有字节数长度补足64字节整倍数所差的字节数,也就是说最初的字节数大于等于64*/
    if(inputlen >= partlen) {
        /*用当前输入的内容把context->buffer的内容补足512bits*/
        memcpy(&buffer[index], input, partlen);

        /*用基本函数对填充满的512bits（已经保存到context->buffer中） 做一次转换，转换结果保存到state中*/
        transform(buffer);
       
        /*
        对当前输入的剩余字节做转换（如果剩余的字节<在输入的input缓冲区中>大于512bits的话 ），
        转换结果保存到state中
        */
        for(i = partlen; i + 64 < inputlen; i += 64) {
            transform(&input[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    /*将输入缓冲区中的不足填充满512bits的剩余内容填充到buffer中，留待以后再作处理*/
    memcpy(&buffer[index], &input[i], inputlen-i);
}

void MD5final(uint1 digest[16], uint1 *context) {
	uint4 index, padLen;
	// 用来补足最后的64bits，也就是8bytes
	uint1 bits[8];
	// 将字符串长度转化
	encode(bits, count, 8);

	 /* 计算所有的bits长度的字节数的模64, 64bytes=512bits*/
    index = (uint4)((count[0] >> 3) & 0x3f);

     /*计算需要填充的字节数，padLen的取值范围在1-64之间*/
    padLen = (index < 56) ? (56 - index) : (120 - index);
    /*这一次函数调用绝对不会再导致MD5Transform的被调用，因为这一次不会填满512bits*/
    update(padding, padLen);
    /*补上原始信息的bits长度（bits长度固定的用64bits表示），这一次能够恰巧凑够512bits，不会多也不会少*/
    update(bits, 8);

    /*将最终的结果保存到digest中。ok，终于大功告成了*/
    encode(digest, state, 16);
}

int main(int argc, char const *argv[]) {

	// 要加密的字符
	uint1 cipertext[1024];
	
	while (scanf("%s", cipertext) != EOF) {
		uint1 digest[16];
		count[1] = count[0] = 0;
		// 对要进行加密的字符加密
		update(cipertext, strlen((char*)cipertext));
		// 获得最最终结果
		MD5final(digest, cipertext);

		// 输出
		for (int i = 0; i < 16; i++) {
			printf("%02x ", digest[i]);
		}
		printf("\n");
		state[0] = 0x67452301;
		state[1] = 0xefcdab89;
		state[2] = 0x98badcfe;
		state[3] = 0x10325476;
	}

	return 0;
}