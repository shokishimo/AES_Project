class AES
{
    /*
        sBox and invSBox are constructed from GF(2^8). The basic principle is that every element
        in GF(2^8) has an inverse. And so invSBox is the inverse of sBox.
        The table is read by row and column. For example (3,5) would be the entry
        containing 0x96 (assuming we start counting at 0).
        Each entry is an integer (in hexadecimal).
        That is for 0x--, Java interprets this as an integer that has the same hex value
        as --. For example: 0x0b is the integer value 62. Or 0xab has integer value 171.
     */
    private static final int[][] sBox =
            {
                    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01,
                            0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
                    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
                            0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
                            0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12,
                            0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b,
                            0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
                            0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9,
                            0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6,
                            0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7,
                            0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
                            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3,
                            0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56,
                            0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd,
                            0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35,
                            0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
                            0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99,
                            0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
            };
    private static final int[][] invSBox =
            {
                    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40,
                            0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
                    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
                            0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
                    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c,
                            0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
                    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b,
                            0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
                    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4,
                            0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
                    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
                            0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
                    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4,
                            0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
                    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf,
                            0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
                    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2,
                            0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
                            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
                    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7,
                            0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
                    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb,
                            0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
                    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12,
                            0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
                    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5,
                            0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
                    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
                            0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
                    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69,
                            0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
            };
    /*
        Some basic conversion methods to be used when needed.
     */
    private static String intToBinary(String s)
    {
        int n = s.length() * 4;
        long l = Long.parseUnsignedLong(s, 16);
        s = Long.toBinaryString(l);
        // Add appropriate number of zeros so that input is the correct length.
        // If input has binary value 0010, then toBinaryString converts to 10.
        // So while loop below will add two 0's to correct the length.
        while (s.length() < n)
            s = "0" + s;
        return s;
    }
    private static String intToBinary(int n)
    {
        String s = Integer.toBinaryString(n);
        while (s.length() < 8)
            s = "0" + s;
        return s;
    }
    private static int binaryToInt(String s)
    {
        return Integer.parseUnsignedInt(s, 2);
    }
    // The xor method is the same as it was in the DES project.
    private static String xor(String a, String b)
    {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < a.length(); i++)
            s.append(a.charAt(i) ^ b.charAt(i));
        s = new StringBuilder(s.toString());
        return s.toString();
    }
    // Allows for xor or two hex numbers (using their int value).
    private static int xor(int n, int m)
    {
        String a = intToBinary(n);
        String b = intToBinary(m);
        return binaryToInt(xor(a,b));
    }
    // Allows us to xor two arrays with hex values (using their int value).
    private static int[] xor(int[] a, int[] b)
    {
        int[] c = new int[a.length];
        for (int i = 0; i < a.length; i++)
            c[i] = xor(a[i], b[i]);
        return c;
    }
    /*
        In GF(2^8), our elements are polynomials of degree 7 or less.
        Each coefficient is 0 or 1. There are two operations in GF(2^8).
        Addition (xor) and multiplication modulo an irreducible polynomial.
        The irreducible polynomial AES uses is
            m(x) = x^8 + x^4 + x^3 + x + 1
        Note only the multiplication operation is modulo m(x). xor is not mod m(x).
        We represent a polynomial by a binary string. The index of the
        string represents the power on the coefficient.
        For example: x^7 + x^5 + x^2 + x + 1 is represented by 10100111.
        Multiplication of two polynomials should be thought of using
        the FOIL method. That way we only have to multiply a polynomial by x^p.
        Then add using the xor operation.
        The xTimes method reads a polynomial (as a binary string) and
        multiplies it by x. Note that if the polynomial a has a 0 coefficient
        in degree 7, this is just a left shift of the binary digits. Note the
        left shift produces a 0 in the furthest right index.
        If there is a 1 in degree 7, then multiplying by x produces a degree
        8 polynomial (not in our space). The operation to produce a degree 7
        polynomial is then to xor the shifted binary string with 00011011.
        See details of this process in the NIST-AES document.
     */
    private static String xTimes(String a)
    {
        String s;
        char msd = a.charAt(0);
        s = a.substring(1) + '0';

        if (msd == '1') { // xor with m(x)
            s = xor(s, "00011011");
        }

        return s;
    }
    /*
        The following method multiplies two polynomials.
        The process works similarly to FOILing. That is multiply
        each term of polynomial p by every term of polynomial q.
        You can use the xTimes method to help with this. For example:
        (x^7 + x^5 + x + 1)(x^3 + x^2 + 1)
        = x^7x^3 + x^7x^2 + x^7 + x^5x^3 + x^5x^2 + x^5 + xx^3 + xx^2 + x + x^3 + x^2 + 1
        = x^7(x^3 + x^2 + 1) + X^5(x^3 + x^2 + 1) + x(x^3 + x^2 + 1) + 1(x^3 + x^2 + 1)
        Use the xor operation for any terms with the same degree.
        See the NIST-AES document for more details of this operation and a good example.
     */
    private static String multiplyPoly(String p, String q)
    {
        String pq = "00000000";
        String xf = q;
        for (int i = p.length()-1; i >= 0; i--) {
            if (p.charAt(i) == '1') {
                pq = xor(pq, xf);
            }
            xf = xTimes(xf);
        }
        return pq;
    }
    /*
        The next method is used when we input the polynomials as an int data type.
        Recall that all our polynomials are thought of as hexadecimal values. Each hex
        value can be thought of as an int data type (see sBox and invSBox above).
     */
    private static int multiplyPoly(int n, int m)
    {
        String p = intToBinary(n);
        String q = intToBinary(m);
        return binaryToInt(multiplyPoly(p,q));
    }
    /*
        The left_circular shift should read in an array and an integer n.
        Then it should apply a left shift by n indices to all
        the entries. The value originally in degree 0 should be placed in the last
        index of the list. The shifted list should be returned.
        For example: [a, b, c, d] ---> [b, c, d, a] is a left shift by 1.
        [a, b, c, d] ---> [c, d, a, b] is a left shift by 2.
    */
    private static int[] leftCircularShift(int[] a, int n)
    {
        if (n == 0)
            return a;
        else
        {
            int[] shiftedArray = new int[a.length];
            for (int i = 0; i < a.length - 1; i++)
                shiftedArray[i] = a[i+1];
            shiftedArray[shiftedArray.length - 1] = a[0];
            return leftCircularShift(shiftedArray,n-1);
        }
    }
    // Similar to the leftCircularShift. Only this time
    // shift to the right.
    private static int[] rightCircularShift(int[] a, int n)
    {
        if (n == 0)
            return a;
        else
        {
            int[] shiftedArray = new int[a.length];
            for (int i = shiftedArray.length - 1; i > 0 ; i--)
                shiftedArray[i] = a[i-1];
            shiftedArray[0] = a[a.length-1];
            return rightCircularShift(shiftedArray,n-1);
        }
    }
    /*
        AES has a 2 dimensional state array that it preforms
        all it's computation on. Think of this as a 4 x 4 matrix
        with hex entries.
        The shiftRows method applies a left circular shift
        to every row. Each row has a shift value of i, where
        i is the index of the row. Note the index starts at
        0 and increases to 3. So the first row in the array
        has index 0 and gets a left shift by 0. The last row
        has index 3 and gets a left shift by 3.
        For example:
        [                           [
            [a, b, c, d]                [a, b, c, d]
            [e, f, g, h]    --->        [f, g, h, e]
            [i, j, k, l]                [k, l, i, j]
            [m, n, o, p]                [p, m, n, o]
        ]                           ]
        The method reads in a 2-dimensional array
        and returns the 2-dimensional array (with the appropriate shift
        applied to each row).
     */
    private static int[][] shiftRows(int[][] m)
    {
        int[][] shiftedRows = new int[m.length][m.length];
        for (int i = 0; i < m.length; i++)
            shiftedRows[i] = leftCircularShift(m[i] ,i);
        return shiftedRows;
    }
    // This method is the same as shiftRows. Only it applies a right
    // circular shift as it is the inverse of the left shift.
    private static int[][] invShiftRows(int[][] m)
    {
        int[][] shiftedRows = new int[m.length][m.length];
        for (int i = 0; i < m.length; i++)
            shiftedRows[i] = rightCircularShift(m[i], i);
        return shiftedRows;
    }
    /*
        tableLookup reads in a 16 bit binary string. It then uses
        this binary string to look up a value in the sBox or invSBox.
        It then splits the binary string into two halves.
        Each half is converted to hexadecimal.
        The left half is used for the row and the right half
        is uses for the column. The method should return the
        hex value table[row][column] (note this will be an int data type).
     */
    private static int tableLookup(String b, int[][] table)
    {
        int row = binaryToInt(b.substring(0, b.length() / 2));
        int column = binaryToInt(b.substring(b.length() / 2));
        return table[row][column];
    }
    // Allows us to call the tableLookup method with hex value (with data type int).
    private static int tableLookup(int n, int[][] table)
    {
        String b = intToBinary(n);
        return tableLookup(b, table);
    }
    /*
        The sBytesTransformation method is the transformation that occurs
        in both the subBytes and invSubBytes methods.
        It applies a transformation of the state
        (remember this is a 4 x 4 matrix or 2-d array).
        The method should transform the state by replacing the values
        in each index by sBox or invSBox of that value.
        The transformed 2-d list should be returned.
        Note subBytes and invSubBytes do the same transformation. The only
        difference is that subBytes uses sBox and invSubBytes uses invSBox.
     */
    private static int[][] sBytesTransformation(int[][] a, int[][] sBox) {
        int[][] b = new int[a.length][a[0].length];
        for (int i = 0; i < a.length; i++)
        {
            for (int j = 0; j < a[i].length; j++)
                b[i][j] = tableLookup(a[i][j], sBox);
        }
        return b;
    }
    private static int[][] subBytes(int[][] a)
    {
        return sBytesTransformation(a, sBox);
    }
    /*
        This method is essentially the same as sub_bytes. Only it should
        use the invSBox table instead of sBox.
     */
    private static int[][] invSubBytes(int[][] a)
    {
        return sBytesTransformation(a, invSBox);
    }
    /*
        The mix_columns method applies a transformation to each
        column in the state using the multiplyPoly method.
        See the NIST-AES document or our book
        for details of how the mixing works.
     */
    private static int[][] mixColumns(int[][] t)
    {
        int[][] s = new int[t.length][t[0].length];
        for (int i = 0; i < 4; i++)
        {
            int product = multiplyPoly(t[0][i], 0x02);
            int productTwo = multiplyPoly(t[1][i], 0x03);
            int result = xor(product, productTwo);
            result = xor(result, t[2][i]);
            s[0][i] = xor(result, t[3][i]);
        }
        for (int i = 0; i < 4; i++)
        {
            int product = multiplyPoly(t[1][i], 0x02);
            int result = xor(t[0][i], product);
            product = multiplyPoly(t[2][i], 0x03);
            result = xor(result, product);
            s[1][i] = xor(result, t[3][i]);
        }
        for (int i = 0; i < 4; i++)
        {
            int result = xor(t[0][i], t[1][i]);
            int product = multiplyPoly(t[2][i], 0x02);
            result = xor(result, product);
            product = multiplyPoly(t[3][i], 0x03);
            s[2][i] = xor(result, product);
        }
        for (int i = 0; i < 4; i++)
        {
            int product = multiplyPoly(t[0][i], 0x03);
            int result = xor(product, t[1][i]);
            result = xor(result, t[2][i]);
            product = multiplyPoly(t[3][i], 0x02);
            s[3][i] = xor(result, product);
        }
        return s;
    }
    /*
        The invMixColumns method is similar to the mixColumns.
        Each column gets an inverse transformation.
        See our book of the NIST-AES document for details
        of how the un-mixing works.
     */
    private static int[][] invMixColumns(int[][] t)
    {
        int[][] s = new int[t.length][t[0].length];
        for (int i = 0; i < 4; i++)
        {
            int product = multiplyPoly(t[0][i], 0x0e);
            int productTwo = multiplyPoly(t[1][i], 0x0b);
            int result = xor(product, productTwo);
            product = multiplyPoly(t[2][i], 0x0d);
            result = xor(result, product);
            product = multiplyPoly(t[3][i], 0x09);
            s[0][i] = xor(result, product);
        }
        for (int i = 0; i < 4; i++)
        {
            int product = multiplyPoly(t[0][i], 0x09);
            int productTwo = multiplyPoly(t[1][i], 0x0e);
            int result = xor(product, productTwo);
            product = multiplyPoly(t[2][i], 0x0b);
            result = xor(result, product);
            product = multiplyPoly(t[3][i], 0x0d);
            s[1][i] = xor(result, product);
        }
        for (int i = 0; i < 4; i++)
        {
            int product = multiplyPoly(t[0][i], 0x0d);
            int productTwo = multiplyPoly(t[1][i], 0x09);
            int result = xor(product, productTwo);
            product = multiplyPoly(t[2][i], 0x0e);
            result = xor(result, product);
            product = multiplyPoly(t[3][i], 0x0b);
            s[2][i] = xor(result, product);
        }
        for (int i = 0; i < 4; i++)
        {
            int product = multiplyPoly(t[0][i], 0x0b);
            int productTwo = multiplyPoly(t[1][i], 0x0d);
            int result = xor(product, productTwo);
            product = multiplyPoly(t[2][i], 0x09);
            result = xor(result, product);
            product = multiplyPoly(t[3][i], 0x0e);
            s[3][i] = xor(result, product);
        }
        return s;
    }
    /*
        128-bit AES generates 10 round keys for the 10 rounds
        of the AES encryption (actually 11 keys, but the first
        key is copied from the input key). Each round key is
        again a 4 x 4 matrix (or 2-D array).
        The addRoundKey method applies a xor operation of the
        state and the round key for each round of the AES algorithm.
        The xor operation is preformed on each index of the matrices.
        See the book or the NIST-AES document for further details.
     */
    private static int[][] addRoundKey(int[][] state, int[][] roundKey)
    {
        int[][] addedState = new int[state.length][state[0].length];
        for (int i = 0; i < state.length; i++)
            addedState[i] = xor(state[i],roundKey[i]);
        return addedState;
    }
    /*
        The following methods are used to generate the round keys.
        We call this process the Key Expansion.
        The key expansion will produce the key schedule. With 128-
        bit AES, this will be 11 roundKeys. Our keyExpansion method
        will create a 2-d array (with length 44) that we will break up into
        11 keys (each will be a 4 x 4 matrix or 2-d array).
        The keyExpansion will use the methods rotWord and subWord.
        The rotWord method is just a left circular shift of an array
        by 1 index.
     */
    private static int[] rotWord(int[] w)
    {
        return leftCircularShift(w,1);
    }
    /*
        The subWord method does an sBox transformation
        applied to each 4 byte word. We will use a 1-d
        array to separate the 4 bytes in a word. Recall
        that a word is 32 bits (or 4 bytes where 1 byte
        is 8 bits).
     */
    private static int[] subWord(int[] w)
    {
        int[] output = new int[w.length];
        for (int i = 0; i < w.length; i++)
            output[i] = tableLookup(w[i], sBox);
        return output;
    }
    // The toHexArray separates a hex key into a 1-d array where each
    // entry in the array is a 2-digit hex number. Remember we use
    // the int data type for each hex number.
    private static int[] toHexArray(String s)
    {
        int[] hexArray = new int[s.length() / 2];
        for (int i = 0; i < s.length(); i+=2)
        {
            String b = s.substring(i, i + 2);
            b = intToBinary(b);
            hexArray[i / 2] = binaryToInt(b);
        }
        return hexArray;
    }
    /*
        The keyExpansion generates an array of 11 words. Each word is 4 bytes
        or 4 2-digit hex numbers. To make things easier to organize, we will
        be treating each word as a 1-d array with 4 2 digit hexadecimal numbers.
        Each round key will contain 4 words. With 11 rounds this gives a total
        of 44 words. And so the expandedKey has length 44.
        Your book does an excellent job of explaining how we fill in this array
        with an example on pg 176. Please look in your book for details and
        NIST_AES document.
        The keyExpansion uses the methods rotWord and subWord. It also
        uses a list of values called rCon. Each value from rCon is a Hex string
        in which each element contains a 2-digit hex number followed by 6 zeros.
        Each value has rCon(i+1) = 2*rCon(i). Note this multiplication is done
        in GF(2^8). That is
            rCon(1) = 01000000
            rCon(2) = 02000000
            rCon(3) = 04000000
            rCon(4) = 08000000
            rCon(5) = 10000000
            rCon(6) = 20000000
            rCon(7) = 40000000
            rCon(8) = 80000000
            rCon(9) = 1b000000
            rCon(10)= 36000000
        Construction of the expandedKey is as follows:
        Let w_i denote the ith word (1-d array of 4 elements).
        In the code below, w_i will be the ith element of the expandedKey array.
        Step 1: Fill the first 4 elements of the expandedKey directly in from the inputted key.
        Step 2: Set i = 0.
        Step 3: Set r_(i) = rotWord(w_(4*i+3))
                    s_(i) = subWord(r_(i))
                    z_(i) = s_(i) xor rCon[i]
        Step 4: Set j = 4*(i+1)
        Step 5: Set w_j =  w_(j-4) xor z_(i)
                    w_(j+1) = w_j xor w_(j-3)
                    w_(j+2) = w_(j+1) xor w_(j-2)
                    w_(j+3) = w_(j+2) xor w_(j-1)
        Step 6: repeat steps 3-6 nine more times for a total of 10 times.
     */
    private static int[][] keyExpansion(String key)
    {
        int[] keyTable = toHexArray(key);
        int[] rCon = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
        int[][] rotWords = new int[10][4];
        int[][] subWords = new int[10][4];
        int[][] z = new int[10][4];
        int[][] expandedKey = new int[44][4];
        // Fill in the first 4 words from the given key.
        for (int j = 0; j < keyTable.length; j+=4)
        {
            for(int i = 0; i < expandedKey[i].length; i++)
            {
                expandedKey[i+j/4][0] = keyTable[j];
                expandedKey[i+j/4][1] = keyTable[j+1];
                expandedKey[i+j/4][2] = keyTable[j+2];
                expandedKey[i+j/4][3] = keyTable[j+3];
            }
        }

        // one way
//        int[] temp;
//        int Nk = 4;
//        int i = Nk;
//
//        while (i < (4 * (10+1))) // Nb * (Nr+1)
//        {
//            temp = expandedKey[i-1];
//            if (i % Nk == 0) {
//                int[] rcons = {rCon[i/Nk-1], 0, 0, 0};
//                temp = xor(subWord(rotWord(temp)), rcons);
//            }
//            expandedKey[i] = xor(expandedKey[i-Nk], temp);
//            i++;
//        }

        // another way
        for (int i = 0; i < 10; i++)
        {
            rotWords[i] = rotWord(expandedKey[4*i+3]);
            subWords[i] = subWord(rotWords[i]);
            int[] rcons = {rCon[i], 0, 0, 0};
            z[i] = xor(subWords[i], rcons);
            int j = 4*(i+1);
            expandedKey[j] = xor(expandedKey[j-4], z[i]);
            expandedKey[j+1] = xor(expandedKey[j], expandedKey[j-3]);
            expandedKey[j+2] = xor(expandedKey[j+1], expandedKey[j-2]);
            expandedKey[j+3] = xor(expandedKey[j+2], expandedKey[j-1]);
        }

        return expandedKey;
    }

    /*
        When AES first reads in a message, it first inputs the message
        into the state. We do this by separating the message into 16
        hex values 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f and inputting them
        into a 4 x 4 matrix (or 2-d array) in the following form:
        0 4 8 c
        1 5 9 d
        2 6 a e
        3 7 b f
        As 2-d arrays usually treat each row as a 1-d array,
        we first write the message in as
        0 1 2 3
        4 5 6 7
        8 9 a b
        c d e f
        Then switch columns and rows.
        The method switchColumnsRows should do this operation.
        That is it should transform
        0 1 2 3                    0 4 8 c
        4 5 6 7        into        1 5 9 d
        8 9 a b        --->        2 6 a e
        c d e f                    3 7 b f
     */
    private static int[][] switchColumnsRows(int[][] matrix)
    {
        int[][] switchArr = new int[4][4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
                switchArr[j][i] = matrix[i][j];
        }
        return switchArr;
    }
    // This method makes a 3-d array
    // that contains all roundKeys (each roundKey
    // is a 2-d array). Each round key is a
    // 4 x 4 matrix. There is a total of 11
    // round keys.
    private static int[][][] getRoundKeys(String key)
    {
        int[][] expandedKey = keyExpansion(key);
        int[][][] roundKeys = new int[11][4][4];
        for (int i = 0; i < expandedKey.length; i+=4)
        {
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                    roundKeys[i/4][j][k] = expandedKey[k + i][j];
            }
        }
        return roundKeys;
    }
    // This method reads in an ASCII message,
    // and sets the initial state.
    private static int[][] initialState(String m)
    {
        int[] messageArray = toHexArray(m);
        int[][] state = new int[4][4];
        for (int i = 0; i < 16; i+=4)
        {
            state[i/4][0] = messageArray[i];
            state[i/4][1] = messageArray[i+1];
            state[i/4][2] = messageArray[i+2];
            state[i/4][3] = messageArray[i+3];
        }
        return switchColumnsRows(state);
    }
    // The toHexBlocks method creates an array of 128-bit
    // hex blocks. A message is read into the method and
    // broken up into 128-bit blocks and stored in an array.
    private static String[] toHexBlocks(String message)
    {
        while (message.length() % 32 != 0)
            message = new StringBuilder().append('0').append(message).toString();
        String[] messageBlocks = new String[message.length() / 32];
        for (int i = 0; i < message.length(); i+=32)
            messageBlocks[i / 32] = message.substring(i, i + 32);
        return messageBlocks;
    }
    /*
        This method simplifies the conversion back to ascii
        step in the decrypt method below. It reads in a string
        (in hex form) and converts the array into a string of their ascii values.
     */
    private static String hexToText(String hexMessage)
    {
        StringBuilder message = new StringBuilder();
        for (int i = 0; i < hexMessage.length(); i+=2)
        {
            String s = hexMessage.substring(i,i+2);
            message.append((char) Integer.parseInt(s,16));
        }
        return message.toString();
    }
    // After encryption or decryption, this method
    // converts the output state to a string
    // of Hex values. Note that if a hex number has
    // one digit, the method adds a 0 to the left of
    // the digit so that the string has the correct
    // length. Every output string should have 32
    // hex digits.
    private static String matrixToString(int[][] m)
    {
        StringBuilder s = new StringBuilder();
        m = switchColumnsRows(m);
        for (int i = 0; i < m.length; i++)
        {
            for (int j = 0; j < m[i].length; j++)
            {
                String t = Integer.toHexString(m[i][j]);
                if (t.length() == 1)
                    s.append("0").append(t);
                else
                    s.append(Integer.toHexString(m[i][j]));
            }
        }
        return s.toString();
    }
    // This method is where all the encryption is done.
    // The cipher first needs to set the state.
    // All operations are preformed on the state
    // Step 1: add the initial round key.
    // Step 2: apply subBytes to state
    // Step 3: shiftRows.
    // Step 4: mixColumns.
    // Step 5: add the round key
    // Step 6: repeat steps 2-5 8 more times
    //          (Steps 2-5 get done a total of 9 times).
    // Step 7: apply subBytes to state.
    // Step 8: shiftRows
    // Step 9: add the last round key.
    // Step 10: return the state.
    public static int[][] cipher(String message, String key)
    {
        int[][] state = initialState(message);
        int[][][] roundKeys = getRoundKeys(key);
        state = addRoundKey(state, roundKeys[0]);
        for (int i = 1; i < 10; i++)
        {
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, roundKeys[i]);
        }
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, roundKeys[10]);

        return state;
    }
    // The invCipher is similar to the cipher method.
    // It essentially runs the cipher in reverse.
    // See our book or the NIST-AES document for details.
    public static int[][] invCipher(String cipherText, String key)
    {
        int[][] state = initialState(cipherText);
        int[][][] roundKeys = getRoundKeys(key);

        state = addRoundKey(state, roundKeys[10]);
        for (int i = 9; i > 0; i--)
        {
            state = invShiftRows(state);
            state = invSubBytes(state);
            state = addRoundKey(state, roundKeys[i]);
            state = invMixColumns(state);
        }
        state = invShiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, roundKeys[0]);

        return state;
    }
    // This method reads in the message, breaks it into
    // 128-bit hex blocks, runs each hex block through cipher,
    // and finally appends together the outputs to make a
    // cipherText string.
    public static String encrypt(String message, String key)
    {
        StringBuilder hexMessage = new StringBuilder();
        for (int i = 0; i < message.length(); i++)
        {
            String hexStr = Integer.toHexString(message.charAt(i));
            hexMessage.append(hexStr);
        }
        String[] hexBlocks = toHexBlocks(hexMessage.toString());
        StringBuilder cipherText = new StringBuilder();
        for (int i = 0; i < hexBlocks.length; i++)
        {
            int[][] matrix = cipher(hexBlocks[i], key);
            String s = matrixToString(matrix);
            cipherText.append(s);
        }
        return cipherText.toString();
    }
    // This method reads in a hex string, separates the string into
    // 128 bit hex blocks, sends each block through invCipher
    // and finally appends the outputs into an ASCII string.
    public static String decrypt(String cipherText, String key)
    {
        StringBuilder hexMessage = new StringBuilder();
        String[] hexBlocks = toHexBlocks(cipherText);
        for (int i = 0; i < hexBlocks.length; i++)
        {
            int[][] matrix = invCipher(hexBlocks[i], key);
            String s = matrixToString(matrix);
            hexMessage.append(s);
        }
        return hexToText(hexMessage.toString());
    }
}