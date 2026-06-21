
F Test Vector
F.1 Blink-64a
m = 0x0
k = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21
6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
t = 0x0123456789abcdef
c = 0xa4a0d10502be846e
F.2 Blink-64b
m = 0x0
k = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21
6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa1
t = 0x0123456789abcdef0123456789abcdef
c = 0x743e142f17caaae1
Jianhua Wang, Tao Huang, Guang Zeng, Tianyou Ding, Shuang Wu and Siwei Sun 35
F.3 Blink-128a
m = 0x0
k = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21
6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f
2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b6
21b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
t = 0x0123456789abcdef0123456789abcdef
c = 0xb722eef350bb182074a6ff13c967a593
F.4 Blink-128b
m = 0x0
k = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21
6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f
2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b6
21b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
t = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
c = 0x20705a38e00412165bdabcac1dcbdec2
F.5 Blink-128A
m = 0x0
k = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21
6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f
2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b6
21b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
28962a4c96893eda752c17026a6395c2d6963be43b2fc10813d73f5a4a48d28d
t = 0x0123456789abcdef0123456789abcdef
c = 0x82449f141c183601195b5046eac2b026
36 THF: Designing Low-Latency Tweakable Block Ciphers
F.6 Blink-128B
m = 0x0
k = 0xd6a102d888a467e4d1d7dec33a246943e07c1dc6f302c57e762c2df9de6f0d21
6dd387874a0b52ce3022e0ad78c78a0697779021b38e7fa15e2b66350517f80f
2961c648d578bae174d70cb769c30a45cc40300fe8a342ca57a0bd0251ae39b6
21b8f104904374bbd6a102e234a664e421b8f104904374bbd6a102d888a666e4
28962a4c96893eda752c17026a6395c2d6963be43b2fc10813d73f5a4a48d28d
t = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
c = 0x8dc41b223bc8cd9923b1297dd27583fc
Jianhua Wang, Tao Huang, Guang Zeng, Tianyou Ding, Shuang Wu and Siwei Sun 37
Table 9: Cell-level differential / linear trail for Blink-64 (Half Cipher)
Half Cipher # of active S-boxes Difference / mask State
3 Rounds 7
1--- 1--- 1--- ----
---- ---- -1-- ----
-1-- 1--1 ---- ----
4 Rounds 16
11-- 1--- 11-- -1--
-1-- ---- -1-- ----
---- 1--- --1- ----
1--- -1-- 11-- --11
5 Rounds 23
1--- ---- 1--- 1---
---- --1- ---- ----
---1 ---- 1--- --1-
1-11 -11- 11-1 -1--
1-1- 11-- 1--- 1--1
6 Rounds 30
1--- 1--- ---- ---1
1-1- --1- ---- 11--
11-- 11-- 111- ----
-1-- 11-- 111- --1-
---1 --11 ---- --11
--1- -1-- ---- --1-
7 Rounds 35
1--- 1--- ---- ---1
1-1- --1- ---- 11--
11-- 11-- 111- ----
-1-- 11-- 111- --1-
---1 --11 ---- --11
--1- -1-- ---- --1-
---- 1--1 1-1- --1-
8 Rounds 38
1--- ---- ---- ----
---- --1- -1-- ---1
-111 1--1 1--- 111-
---- 1-11 11-- 1111
---- -111 -111 -111
---- 1--- 1--- 1---
1--- ---- ---- ----
---- --1- -1-- ---1
38 THF: Designing Low-Latency Tweakable Block Ciphers
Table 10: Cell-level differential / linear trail for Blink-64 (Full Cipher)
Full Cipher # of active S-boxes Difference / mask State
4 Rounds 16
1--- ---- 1--- 1---
---- --1- ---- ----
--1- ---- --1- --1-
-111 -111 --1- -1-1
6 Rounds 24
--11 --11 ---- ----
---- -1-- 1--- 11--
-1-- ---1 -1-- ---1
-1-- ---1 -1-- ---1
---- -1-- 1--- 11--
--11 --11 ---- ----
8 Rounds 32
1--- ---- 1--- 1---
---- --1- ---- ----
---1 ---- 1--- --1-
1-11 -11- 11-1 -1--
1-11 -11- 11-1 -1--
---1 ---- 1--- --1-
---- --1- ---- ----
1--- ---- 1--- 1---
10 Rounds 50
1--- ---- 1--- 1---
---- --1- ---- ----
---1 ---- 1--- --1-
1-11 -11- 11-1 -1--
1-11 11-- 1--- 1-11
-111 1--- 11-- -111
-11- -1-1 1-11 1-1-
-1-- ---1 --1- ----
-1-- ---- ---- ----
-1-- ---- -1-- -1--
12 Rounds 64
1-1- 111- -1-- ---1
111- -11- 1-1- 11--
---- --1- --1- --1-
---- ---- 1--- ----
1--- --1- -1-- ----
-1-1 1-11 11-- --11
-1-1 1-11 11-- --11
1--- --1- -1-- ----
---- ---- 1--- ----
---- --1- --1- --1-
111- -11- 1-1- 11--
1-1- 111- -1-- ---1
Jianhua Wang, Tao Huang, Guang Zeng, Tianyou Ding, Shuang Wu and Siwei Sun 39
Table 11: Cell-level differential / linear trail for Blink-128 (Half Cipher)
Half Cipher # of active S-boxes Difference / mask State
3 Rounds 7
1------- 1------- -------- 1-------
-------1 -------- -------- --------
-------- -------- -------- -1-1-1--
4 Rounds 16
------1- -1----1- -1------ -1----1-
---1---- ---1---- -------- --------
-------- ----1--- ---1---- --------
--1----- 1---11-- ---1---1 --------
5 Rounds 24
-------- -1----11 -1----11 ------11
----11-- -------- -----1-- ----1---
1-1----- 1-1----- -------- --------
------1- ------1- 1------- 1-------
-------1 -1------ -----1-- --1-----
6 Rounds 36
-------- -1----11 -1----11 ------11
----11-- -------- -----1-- ----1---
1-1----- 1-1----- -------- --------
------1- ------1- 1------- 1-------
-------1 -1------ -----1-- --1-----
1--11-1- -------1 111----- -1-1-11-
7 Rounds 48
1---11-- 1-1----- 1---1--- --1-----
--1---1- --1----1 -------1 --1---11
-------- -------- --1-11-- ----1---
1-----1- 1------1 1------1 ------11
-------- -------- ----11-- --1-1---
1-----1- 1------1 1-1----1 ------1-
------1- -------- 1---11-- -11--1-1
8 Rounds 58
--11---- --1--1-- --11---- -----1--
-------- -------1 ---1--1- ------11
-------- ---111-- ---11--- ---1-1--
-1------ -------1 ---1---1 ------1-
----11-- -1-111-- -1-1-1-- -1-111--
---1---- -------1 ---1---1 ------1-
-------- -1-1---- ---1-11- -1---1--
-----1-- -11-1--- -1--111- ------1-
40 THF: Designing Low-Latency Tweakable Block Ciphers
Table 12: Cell-level differential / linear trail for Blink-128 (Full Cipher)
Full Cipher # of active S-boxes Difference / mask State
4 Rounds 16
-------- -----1-- 1-1--1-- 1-1-----
-------1 --1----1 --1----- --1----1
--1----- -------- -------1 --------
----1--- -------- ----1--- --------
6 Rounds 24
----11-- -------- -----1-- ----1---
1-1----- 1-1----- -------- --------
------1- ------1- 1------- 1-------
------1- ------1- 1------- 1-------
1-1----- 1-1----- -------- --------
----11-- -------- -----1-- ----1---
8 Rounds 40
-------- -1----11 -1----11 ------11
----11-- -------- -----1-- ----1---
1-1----- 1-1----- -------- --------
------1- ------1- 1------- 1-------
------1- ------1- 1------- 1-------
1-1----- 1-1----- -------- --------
----11-- -------- -----1-- ----1---
-------- -1----11 -1----11 ------11
10 Rounds 64
-1----1- -1------ -1----1- ------1-
-------- -1------ -1------ --------
----11-- -------- -------- --------
-1------ 1-1----1 -------1 ------1-
----11-1 -1-1---- 111--1-- 111111-1
----11-1 -1-1---- 111--1-- 111111-1
-1------ 1-1----1 -------1 ------1-
----11-- -------- -------- --------
-------- -1------ -1------ --------
-1----1- -1------ -1----1- ------1-
Table 13: Cell-level impossible differential trail for Blink-64 (Full Cipher)
Full Cipher Difference
6 + 0 Rounds 1--- ---- ---- ----
1--- ---- ---- ----
5 + 2 Rounds 1--- ---- ---- ----
1--- ---- ---- ----
3 + 3 Rounds 1--- ---- ---- ----
1--- ---- ---- ----
Jianhua Wang, Tao Huang, Guang Zeng, Tianyou Ding, Shuang Wu and Siwei Sun 41
Table 14: Cell-level impossible differential trail for Blink-128 (Full Cipher)
Full Cipher Difference
9 + 0 Rounds 1------- -------- -------- --------
-------- ------1- -------- --------
8 + 1 Rounds 1------- -------- -------- --------
-------- 1------- -------- --------
7 + 2 Rounds 1------- -------- -------- --------
--1----- -------- -------- --------
6 + 3 Rounds 1------- -------- -------- --------
----1--- -------- -------- --------
5 + 4 Rounds 1------- -------- -------- --------
-------- ----1--- -------- --------
Table 15: Division trail for Blink-64 (Half Cipher)
Round Index Operation State
Input 7fff ffff ffff ffff
Round 1
S 4fff ffff ffff ffff
M dfff 7fff ffff efff
P dfff ff7f feff ffff
Round 2
S 9fff ff4f f2ff ffff
M deef ffdf b77f fbff
P dff7 edfb ef7f fffb
Round 3
S 1ff1 21f2 2f4f fff2
M 6dd7 0b7a b7e0 3ff3
P 6b0e d70f d373 7afb
Round 4
S 8c08 110f 7121 4cfc
M 706b ddbd 0d0d 0000
P 7dd0 0bd0 60d0 bd00
Round 5
S 4810 0220 2040 8400
M 0000 e000 0e00 0070
P 0000 00e0 00e0 0070
Round 6
S 0000 0020 0080 0040
M 00e0 0000 0000 0000
P 0000 0000 e000 0000
Round 7
S 0000 0000 8000 0000
M 8000 0000 0000 0000
P 8000 0000 0000 0000
Output 8000 0000 0000 0000
42 THF: Designing Low-Latency Tweakable Block Ciphers
Table 16: Division trail for Blink-128 (Half Cipher)
Round Index Operation State
Input 7fffffff ffffffff ffffffff ffffffff
Round 1
S 1fffffff ffffffff ffffffff ffffffff
M dfffffff ffffffff bfffffff 7fffffff
P fffffffb ffffffff ffffffff df7fffff
Round 2
S fffffff2 ffffffff ffffffff df4fffff
M dfeffff7 ff7ffffe ffffffff ffdffffb
P ffffff7f ffffffff efffffff dffb7efd
Round 3
S ffffff9f ffffffff 9fffffff 7ff8a2f4
M fffbf7de dffdefb7 7ffebbff bffffefd
P 7efffff7 fbbfdfdf fffbfdeb ffbde7ef
Round 4
S 48fffff4 fb8f8f2f fff2f49c ffb482ef
M eedfd0ec fbeedfff ddb7e70d 7bb0eeb6
P 0ddedbed ef70e0ff dbbfbe7e ed76cfeb
Round 5
S 01484821 8f1090ff 482f2218 28441f82
M eb4c9008 09007bb3 0c000e0d 007f50f3
P 079bc900 5be00f0b 400cf000 ed038307
Round 6
S 04422100 48800f08 8004f001 21011804
M e000bb0d 00070000 0dc00d00 00007000
P b0b0d000 70d07000 00c00000 e000d000
Round 7
S 80202000 40104000 00400000 20008000
M 00000000 00000000 e000e000 00700000
P 0000000e 00000000 0000000e 00000007
Round 8
S 00000008 00000000 00000002 00000001
M 00000000 0000000b 00000000 00000000
P 00000000 00000000 00000000 00000b00
Round 9
S 00000000 00000000 00000000 00000800
M 00000800 00000000 00000000 00000000
P 80000000 00000000 00000000 00000000
Output 80000000 00000000 00000000 00000000
