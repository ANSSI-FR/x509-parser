/*
 *  Copyright (C) 2022 - This file is part of x509-parser project
 *
 *  Author:
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *
 *  This software is licensed under a dual GPLv2/BSD license. See
 *  LICENSE file at the root folder of the project.
 */

#include "x509-parser.h"
#include "x509-parser-internal-decl.h"

/*
 * Some implementation notes:
 *
 * The implementation is based on X.690 and X.680 (both 07/2002). It is
 * voluntarily limited to parsing a buffer of small size (no more than
 * ASN1_MAX_BUFFER_SIZE bytes long) containing a DER encoded ASN.1
 * structure.
 *
 */

#ifdef ERROR_TRACE_ENABLE
#define ERROR_TRACE_APPEND(x) do {			    \
	       extern int printf(const char *format, ...);  \
	       printf("%05d ", (x));			    \
	} while (0);
#else
#define ERROR_TRACE_APPEND(x)
#endif

typedef enum {
	CLASS_UNIVERSAL = 0x00,
	CLASS_APPLICATION = 0x01,
	CLASS_CONTEXT_SPECIFIC = 0x02,
	CLASS_PRIVATE = 0x03
} tag_class;

/*@
  @ predicate bmatch(u8 *b1, u8 *b2, u32 n) =
  @   \forall integer i; 0 <= i < n ==> b1[i] == b2[i];
  @
  @ predicate bdiffer(u8 *b1, u8 *b2, u32 n) =
  @   ! bmatch(b1, b2, n);
  @*/
/*@
  @
  @ requires \valid_read(b1 + (0 .. n-1));
  @ requires \valid_read(b2 + (0 .. n-1));
  @
  @ assigns \nothing;
  @*/
static int bufs_differ(const u8 *b1, const u8 *b2, u32 n)
{
	int ret = 0;
	u32 i = 0;

	/*@
	  @ loop invariant 0 <= i <= n;
	  @ loop invariant bmatch(b1, b2, i);
	  @ loop assigns i;
	  @ loop variant n - i;
	  @*/
	for (i = 0; i < n; i++) {
		if(b1[i] != b2[i]) {
			ret = 1;
			break;
		}
	}

	return ret;
}

/*
 * Helper for ASN.1 DER identifier field parsing, which extracts the tag number
 * when it is not encoded on a single byte, i.e. when the first encountered byte
 * for the field is 0x1f. The function takes as parameter the buffer following
 * this 0x1f byte and, upon success, extracts the tag value.
 *
 * In our implementation, tag numbers are limited by the return type used for
 * the parameter (32 bit unsigned integers). In practice we allow tag encoded
 * on 4 bytes, i.e. with a final value of 4 * 7 bits, i.e. 28 bits. This is
 * considered largely sufficient in the context of X.509 certificates (which is
 * validated by our tests).
 *
 * Note that the function does verify that extracted tag is indeed >= 0x1f.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(tag_num);
  @ requires \valid(eaten);
  @ requires \separated(tag_num, eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> 1 <= *eaten <= len;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten > 0);
  @
  @ assigns *tag_num, *eaten;
  @*/
static int _extract_complex_tag(const u8 *buf, u32 len, u32 *tag_num, u32 *eaten)
{
	u32 rbytes;
	u32 t = 0;
	int ret;

	if ((len == 0) || (buf == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len > 4) {
		len = 4;
	}

	/*@ loop unroll 4;
	  @ loop invariant 0 <= rbytes <= len;
	  @ loop invariant t <= (((u32)1 << (u32)(7*(rbytes))) - 1);
	  @ loop invariant \forall integer x ; 0 <= x < rbytes ==>
		 ((buf[x] & 0x80) != 0);
	  @ loop assigns rbytes, t;
	  @ loop variant (len - rbytes);
	  @ */
	for (rbytes = 0; rbytes < len; rbytes++) {
		u32 tmp1, tmp2;
		/*@ assert rbytes <= 3; */
		/*@ assert t <= (((u32)1 << (u32)(7*(rbytes))) - 1); */
		/*@ assert t <= (u32)0x1fffff; */
		tmp1 = (t << (u32)7);
		tmp2 = ((u32)buf[rbytes] & (u32)0x7f);
		/*@ assert tmp1 <= (u32)0xfffff80; */
		/*@ assert tmp2 <= (u32)0x7f; */
		t = tmp1 + tmp2;
		/*@ assert t <= (((u32)1 << (u32)(7*(rbytes + 1))) - 1); */
		/*@ assert t <= 0xfffffff; */

		if ((buf[rbytes] & 0x80) == 0) {
			break;
		}
	}

	/* Check if we left the loop w/o finding tag's end */
	if (rbytes == len) {
		/*@ assert ((buf[len - 1] & 0x80) != 0); */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (t < 0x1f) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*tag_num = t;
	*eaten = rbytes + 1;

	ret = 0;

out:
	return ret;
}

/*
 * Parse beginning of current buffer to get the identifier parameters (class,
 * P/C flag and tag number). On success, the amount of bytes eaten to extract
 * those information is returned in 'eaten' parameter, which is guaranteed to
 * be lower or equal than 'len' parameter. On error, a non-zero negative value
 * is returned.
 *
 * Note: tags numbers are limited by the return type used for the parameter
 * (32 bit unsigned integer). In practice, this allows tag encoded on 4 bytes,
 * i.e. 4 x 7 bits, i.e. 28 bits. This is considered largely sufficient in
 * the context of X.509 certificates. An error is returned if a tag number
 * higher than that is found.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==>
	     \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(cls);
  @ requires \valid(prim);
  @ requires \valid(tag_num);
  @ requires \valid(eaten);
  @ requires \separated(cls, prim, tag_num, eaten, buf+(..));
  @
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (0 < *eaten <= len);
  @ ensures (\result == 0) ==> (*cls <= 0x3);
  @ ensures (\result == 0) ==> (*prim <= 0x1);
  @
  @ assigns *tag_num, *eaten, *prim, *cls;
  @*/
static int get_identifier(const u8 *buf, u32 len,
			  tag_class *cls, u8 *prim, u32 *tag_num, u32 *eaten)
{
	int ret;
	u32 t;
	u32 rbytes = 0;
	u8 p;
	tag_class c;

	if (buf == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * First byte (if available) will give us the class and P/C, and also
	 * tells us (based on the value of the 6 LSB of the bytes) if the tag
	 * number is stored on additional bytes.
	 */
	if (len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* See 8.1.2.3 */
	c = (buf[0] >> 6) & 0x03; /* Extract class from 2 MSB */
	p = (buf[0] >> 5) & 0x01; /* Extract P/C bit */
	t = buf[0] & 0x1f;        /* Extract tag number from 6 LSB */
	rbytes = 1;

	/*
	 * Check if we know given class (see Table 1 from 8.1.2.2). In practice,
	 * there is no way to end up in default case, because 'c' has at most
	 * its two MSB set (see above).
	 */
	switch (c) {
	case CLASS_UNIVERSAL:
	case CLASS_APPLICATION:
	case CLASS_CONTEXT_SPECIFIC:
	case CLASS_PRIVATE:
		break;
	default:
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;
	}

	/*
	 * If the tag number (6 LSB of first byte) we already extracted is less
	 * than 0x1f, then it directly represents the tag number (which is <=
	 * 30) and our work is over. Otherwise (t == 0x1f) the real tag number
	 * is encoded on multiple bytes following the first byte. Note that we
	 * limit ourselves to tag encoded on less than 28 bits, i.e. only accept
	 * at most 4 bytes (only 7 LSB of each byte will count because MSB tells
	 * if this is the last).
	 */
	if (t == 0x1f) {
		u32 tag_len = 0;

		/*@
		  @ assert (len >= rbytes) &&
		    \valid_read(buf + (rbytes .. len - 1));
		  @*/
		ret = _extract_complex_tag(buf + rbytes, len - rbytes,
					   &t, &tag_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		rbytes += tag_len;
	}

	/* Export what we extracted to caller */
	*cls = c;
	*prim = p;
	*tag_num = t;
	*eaten = rbytes;

	ret = 0;

out:
	return ret;
}

/*
 * Parse beginning of current buffer to get the length parameter. Input buffer
 * 'buf' has size 'len'. On success, 0 is returned, advertised length is
 * returned in 'adv_len' and the number of bytes used for the encoding of the
 * length is returned in 'eaten'.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(adv_len);
  @ requires \valid(eaten);
  @ requires \separated(adv_len, eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (0 < *eaten <= len);
  @ ensures (\result == 0) ==> (*adv_len <= len);
  @ ensures (\result == 0) ==> ((*adv_len + *eaten) <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *adv_len, *eaten;
  @*/
static int get_length(const u8 *buf, u32 len, u32 *adv_len, u32 *eaten)
{
	u32 l, rbytes = 0;
	u32 len_len, b0;
	int ret;

	if (buf == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + 0); */
	b0 = buf[0];

	/* Single byte length (i.e. definitive form, on one byte)? */
	if ((b0 & 0x80) == 0) {
		l = b0 & 0x7f;
		/*@ assert l <= 0x7f ; */

		/*
		 * Adding 1 below to take into account the byte that
		 * encode the length is possible because l does not
		 * have its MSB set, i.e. is less than or equal to
		 * 127.
		 */
		if ((l + 1) > len) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/* Advertised length looks ok */
		*eaten = 1;
		*adv_len = l;
		/*@ assert (*eaten + *adv_len) <= len ; */
		ret = 0;
		goto out;
	}

	/*
	 * DER requires the definitive form for the length, i.e. that
	 * first byte of the length field is not 0x80. At that point,
	 * we already know that MSB of the byte is 1.
	 */
	if (b0 == 0x80) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We now know that the long form of the length is used. Let's
	 * extract how many bytes are used to encode the length.
	 */
	len_len = b0 & 0x7f;
	/*@ assert len_len <= 0x7f ; */
	rbytes += 1;
	/*@ assert rbytes > 0 ; */

	/*
	 * We first check that given length for the length field is not
	 * more than the size of the buffer (including the first byte
	 * encoding the length of that length). Note that we can do
	 * the addition below because MSB of len_len is 0.
	 */
	if ((len_len + 1) > len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Now that we have length's length, let's now extract its value */
	switch (len_len) {
	case 0: /* Not acceptable */
		/* Length's length cannot be 0 */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;

	case 1: /* Length values in [ 128, 255 ] */
		/* assert \valid_read(buf + 1); */
		l = buf[1];
		if (l <= 127) {
			/*
			 * For such a length value, the compact encoding
			 * (definitive form) should have been used.
			 */
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		/*@ assert 127 < l ; */
		rbytes += 1;
		break;

	case 2: /* Length values in [ 256, 65535 ] */
		/* assert \valid_read(buf + (1 .. 2)); */
		l = (((u32)buf[1]) << 8) + buf[2];
		if (l <= 0xff) {
			/* Why 2 bytes if most significant is 0? */
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		/*@ assert 0xff < l <= 0xffff ; */
		rbytes += 2;
		break;

	case 3: /* Length values in [ 65536, 16777215 ] */
		/* assert \valid_read(buf + (1 .. 3)); */
		l = (((u32)buf[1]) << 16) + (((u32)buf[2]) << 8) + buf[3];
		if (l <= 0xffff) {
			/* Why 3 bytes if most significant is 0? */
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		/*@ assert 0xffff < l <= 0xffffff ; */
		rbytes += 3;
		break;

	case 4: /* Length values in [ 16777215, 4294967295 ] */
		/* assert \valid_read(buf + (1 .. 4)); */
		l = (((u32)buf[1]) << 24) + (((u32)buf[2]) << 16) + (((u32)buf[3]) << 8) + buf[4];
		if (l <= 0xffffff) {
			/* Why 4 bytes if most significant is 0? */
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		/*@ assert 0xffffff < (u64)l <= 0xffffffff ; */
		rbytes += 4;
		break;

	default: /* Not acceptable */
		/*
		 * Length cannot be encoded on more than fours bytes (we
		 * have an *intentional* internal limitation for
		 * all ASN.1 DER structures set to 2^32 - 1 bytes (all
		 * our lengths are u32)
		 */
		 ret = -__LINE__;
		 ERROR_TRACE_APPEND(__LINE__);
		 goto out;
		 break;
	}

	/*@ assert l > 127 ; */
	/*@ assert len >= rbytes ; */
	if ((len - rbytes) < l) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert (rbytes + l) <= len ; */
	/*@ assert rbytes > 0 ; */
	*eaten = rbytes;
	*adv_len = l;

	ret = 0;

out:
	return ret;
}

typedef enum {
	ASN1_TYPE_BOOLEAN         = 0x01,
	ASN1_TYPE_INTEGER         = 0x02,
	ASN1_TYPE_BIT_STRING      = 0x03,
	ASN1_TYPE_OCTET_STRING    = 0x04,
	ASN1_TYPE_NULL            = 0x05,
	ASN1_TYPE_OID             = 0x06,
	ASN1_TYPE_SEQUENCE        = 0x10,
	ASN1_TYPE_SET             = 0x11,
	ASN1_TYPE_PrintableString = 0x13,
	ASN1_TYPE_T61String       = 0x14,
	ASN1_TYPE_IA5String       = 0x16,
	ASN1_TYPE_UTCTime         = 0x17,
	ASN1_TYPE_GeneralizedTime = 0x18,
} asn1_type;

/*
 * All DER-encoded elements are basically TLV structures (or identifier octets,
 * length octets, contents octets). This function parses the T and L elements
 * from given buffer and verifies the advertised length for the value (content
 * octets) does not overflow outside of the buffer. Additionally, the expected
 * class and type for the tag are verified. On success, the size of parsed
 * elements (class, type and length) are returned in 'parsed' and the size of
 * content octets are returned in 'content_len'.
 *
 * Note that the function does not parse the content of the encoded value, i.e.
 * the 'content_len' bytes in the buffer after the 'parsed' (TL header) ones. It
 * only guarantees that they are in the buffer.
 *
 * This function is critical for the security of the module.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(parsed);
  @ requires \valid(content_len);
  @ requires \separated(parsed, content_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *parsed <= len);
  @ ensures (\result == 0) ==> (*content_len <= len);
  @ ensures (\result == 0) ==> (1 < (*content_len + *parsed) <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *parsed, *content_len;
  @*/
static int parse_id_len(const u8 *buf, u32 len, tag_class exp_class,
			u32 exp_type, u32 *parsed, u32 *content_len)
{
	tag_class c = 0;
	u8 p;
	u32 t = 0;
	u32 cur_parsed = 0;
	u32 grabbed;
	u32 adv_len = 0;
	int ret;

	if (buf == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Get the first part of the encoding, i.e. the identifier */
	ret = get_identifier(buf, len, &c, &p, &t, &cur_parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert cur_parsed > 0; */

	/*
	 * Now, verify we are indeed dealing with an element of
	 * given type ...
	 */
	if (t != exp_type) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* ... and class. */
	if (c != exp_class) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	grabbed = cur_parsed;
	/*@ assert grabbed > 0; */
	len -= cur_parsed;
	buf += cur_parsed;

	/* Get the second part of the encoding, i.e. the length */
	ret = get_length(buf, len, &adv_len, &cur_parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert cur_parsed > 0; */

	grabbed += cur_parsed;
	/*@ assert grabbed > 1; */
	len -= cur_parsed;
	buf += cur_parsed;

	/* Verify advertised length is smaller than remaining buffer length */
	if (adv_len > len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*parsed = grabbed;
	/*@ assert *parsed > 1; */
	*content_len = adv_len;

	ret = 0;

out:
	return ret;
}

/*
 * Here, we have to deal with a wrapper around our a usual ASN.1 TLV.
 * The id of that wrapper has a given type and a context specific
 * class (CLASS_CONTEXT_SPECIFIC), i.e. a T1L1T2L2V where
 * T1 has exp_ext_type and class CLASS_CONTEXT_SPECIFIC
 * L1 provides the length of T2L2V
 * T2 has exp_int_type and exp_int_class
 * L2 provides the length of V
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(parsed);
  @ requires \valid(data_len);
  @ requires \separated(parsed, data_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*parsed <= len);
  @ ensures (\result == 0) ==> (*data_len <= len);
  @ ensures (\result == 0) ==> ((*data_len + *parsed) <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *parsed, *data_len;
  @*/
static int parse_explicit_id_len(const u8 *buf, u32 len,
				 u32 exp_ext_type,
				 tag_class exp_int_class, u32 exp_int_type,
				 u32 *parsed, u32 *data_len)
{
	u32 hdr_len = 0;
	u32 val_len = 0;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Work on external packaging */
	ret = parse_id_len(buf, len, CLASS_CONTEXT_SPECIFIC,
			   exp_ext_type, &hdr_len, &val_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	len -= hdr_len;
	*parsed = hdr_len;

	/* Work on internal packaging */
	ret = parse_id_len(buf, len, exp_int_class, exp_int_type,
			   &hdr_len, &val_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	len -= hdr_len;
	*parsed += hdr_len;
	if (len < val_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Export the size of data */
	*data_len = val_len;

	ret = 0;

out:
	return ret;
}


/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(arc_val);
  @ requires \valid(eaten);
  @ requires \separated(arc_val, eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten > 0);
  @ ensures ((len > 0) && (buf != \null) && (\result != 0)) ==>
	    \forall integer x ; 0 <= x < \min(len, 4) ==>
	    ((buf[x] & 0x80) != 0);
  @ ensures (len == 0) ==> \result < 0;
  @
  @ assigns *arc_val, *eaten;
  @*/
static int _parse_arc(const u8 *buf, u32 len, u32 *arc_val, u32 *eaten)
{
	u32 rbytes;
	u32 av = 0;
	int ret;

	if ((len == 0) || (buf == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * RFC 5280 has "There is no maximum size for OIDs. This specification
	 * mandates support for OIDs that have arc elements with values that
	 * are less than 2^28, that is, they MUST be between 0 and 268,435,455,
	 * inclusive. This allows each arc element to be represented within a
	 * single 32-bit word." For that reason, we just leave if we end up
	 * encountering more than 4 bytes here.
	 */
	if (len > 4) {
		len = 4;
	}

	/*@ loop unroll 4;
	  @ loop invariant 0 <= rbytes <= len;
	  @ loop invariant av <= (((u32)1 << (u32)(7*(rbytes))) - 1);
	  @ loop invariant \forall integer x ; 0 <= x < rbytes ==>
		 ((buf[x] & 0x80) != 0);
	  @ loop assigns rbytes, av;
	  @ loop variant (len - rbytes);
	  @ */
	for (rbytes = 0; rbytes < len; rbytes++) {
		u32 tmp1, tmp2;

		/*@ assert rbytes <= 3; */
		/*@ assert av <= (((u32)1 << (u32)(7*(rbytes))) - 1); */
		/*@ assert av <= (u32)0x1fffff; */

		tmp1 = (av << (u32)7);
		/*@ assert tmp1 <= (u32)0xfffff80; */
		tmp2 = ((u32)buf[rbytes] & (u32)0x7f);
		/*@ assert tmp2 <= (u32)0x7f; */
		av = tmp1 + tmp2;
		/*@ assert av <= (((u32)1 << (u32)(7*(rbytes + 1))) - 1); */
		/*@ assert av <= 0xfffffff; */

		if ((buf[rbytes] & 0x80) == 0) {
			break;
		}
	}

	if (rbytes >= len) {
		/*@ assert ((buf[len - 1] & 0x80) != 0); */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*arc_val = av;
	*eaten = rbytes + 1;

	ret = 0;

out:
	return ret;
}


static const u8 null_encoded_val[] = { 0x05, 0x00 };

/*
 * Implements a function for parsing ASN1. NULL object. On success, the function
 * returns 0 and set 'parsed' parameters to the amount of bytes parsed (i.e. 2).
 * -1 is returned on error.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(parsed);
  @ requires \separated(parsed, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> *parsed == 2;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *parsed;
  @*/
static int parse_null(const u8 *buf, u32 len, u32 *parsed)
{
	int ret;

	if ((len == 0) || (buf == NULL) || (parsed == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len != sizeof(null_encoded_val)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = bufs_differ(buf, null_encoded_val, sizeof(null_encoded_val));
	if (ret) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;
	*parsed = sizeof(null_encoded_val);

out:
	return ret;
}

/*
 * Implements a function for parsing OID as described in section 8.19
 * of X.690. On success, the function returns 0 and set 'parsed'
 * parameters to the amount of bytes on which the OID is encoded
 * (header and content bytes).
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(parsed);
  @ requires \separated(parsed,buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < *parsed <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *parsed;
  @*/
static int parse_OID(const u8 *buf, u32 len, u32 *parsed)
{
	u32 data_len = 0;
	u32 hdr_len = 0;
	u32 remain = 0;
	u32 num;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_OID,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	len -= hdr_len;
	buf += hdr_len;
	if (data_len < 1) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert \valid_read(buf + (0 .. (data_len - 1))); */

	remain = data_len;
	num = 0;

	/*@
	  @ loop assigns ret, num, buf, remain;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop variant remain;
	  @ */
	while (remain) {
		u32 arc_val = 0;
		u32 rbytes = 0;

		/*
		 * RFC 5280 has "Implementations MUST be able to handle
		 * OIDs with up to 20 elements (inclusive)".
		 */
		if (num > 20) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		ret = _parse_arc(buf, remain, &arc_val, &rbytes);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*@ assert rbytes <= remain ; */

		num += 1;

		buf += rbytes;
		remain -= rbytes;
	}

	/*
	 * Let's check the OID had at least the first initial
	 * subidentifier (the one derived from the two first
	 * components) as described in section 8.19 of X.690.
	 */
	if (num < 1) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*parsed = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/*
 * Implements a function for parsing integers as described in section 8.3
 * of X.690. As integers may be used in a context specific way, we allow
 * passing the expected class and type values which are to be found. The
 * parameter pos_or_zero allows specifying if only non-negative integer
 * (postive or zero) should be accepted. When set, the function returns
 * a non zero value when the parsed integer is negative. The functions
 * is not expected to be used directly but only as a helper in the
 * two function that follows it.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(hdr_len);
  @ requires \valid(data_len);
  @ requires \separated(hdr_len, data_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> ((u64)2 < ((u64)*hdr_len + (u64)*data_len) <= (u64)len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *hdr_len, *data_len;
  @*/
static int _parse_integer(const u8 *buf, u32 len,
			  tag_class exp_class, u32 exp_type,
			  u32 *hdr_len, u32 *data_len,
			  int pos_or_zero)
{
	int ret;

	if ((buf == NULL) || (len == 0) || (hdr_len == NULL) || (data_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*hdr_len = 0;
	*data_len = 0;
	ret = parse_id_len(buf, len, exp_class, exp_type, hdr_len, data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += *hdr_len;

	/*
	 * Regarding integer encoding, 8.3.1 of X.690 has "The contents octets
	 * shall consist of one or more octets".
	 */
	if (*data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * On integer encoding, 8.3.2 of x.690 has "If the contents octets of
	 * an integer value encoding consist of more than one octet, then the
	 * bits of the first octet and bit 8 of the second octet:
	 *
	 *  a) shall not all be ones; and
	 *  b) shall not all be zero.
	 */
	if (*data_len > 1) {
		if ((buf[0] == 0) && ((buf[1] & 0x80) == 0)) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		if ((buf[0] == 0xff) && (buf[1] & 0x80)) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	if (pos_or_zero && (buf[0]) & 0x80) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * Common version. Allow positive and negative integers.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(hdr_len);
  @ requires \valid(data_len);
  @ requires \separated(hdr_len, data_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < ((u64)*hdr_len + (u64)*data_len) <= (u64)len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *hdr_len, *data_len;
  @*/
static inline int parse_integer(const u8 *buf, u32 len,
				tag_class exp_class, u32 exp_type,
				u32 *hdr_len, u32 *data_len)
{
	return _parse_integer(buf, len, exp_class, exp_type,
			      hdr_len, data_len, 0);
}

/*
 * Same as previous but additionally enforce the value at hand is not negative,
 * i.e. positive or 0. This is for instance useful for integer encoding value
 * that are reduced modulo another value (e.g. ECDSA signature components).
 * The function returns 0 when the integer is valid and positive.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(hdr_len);
  @ requires \valid(data_len);
  @ requires \separated(hdr_len, data_len, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < ((u64)*hdr_len + (u64)*data_len) <= (u64)len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *hdr_len, *data_len;
  @*/
static inline int parse_non_negative_integer(const u8 *buf, u32 len,
					     tag_class exp_class, u32 exp_type,
					     u32 *hdr_len, u32 *data_len)
{
	return _parse_integer(buf, len, exp_class, exp_type,
			      hdr_len, data_len, 1);
}

/*
 * Implements a function for parsing booleans as described in section 8.2
 * of X.690. When encoded in DER, a boolean is a 3 bytes elements which
 * can take a value of:
 *
 *  FALSE : { 0x01, 0x01, 0x00 }
 *  TRUE  : { 0x01, 0x01, 0xff }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \separated(eaten, buf+(..));
  @ requires \valid(eaten);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_boolean(const u8 *buf, u32 len, u32 *eaten)
{
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len < 3) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if ((buf[0] != ASN1_TYPE_BOOLEAN) || (buf[1] != 0x01)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	switch (buf[2]) {
	case 0x00: /* FALSE */
	case 0xff: /* TRUE  */
		break;
	default:
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;
	}

	*eaten = 3;

	ret = 0;

out:
	return ret;
}

/*
 * The implementation is based on 4.1 and 4.1.2.1 of RFC5280 + Section
 * 8.3 of X.690. The version field is mandatory and it is encoded as
 * an integer. As we only limit ourselves to version 3 certificates
 * (i.e. a value of 0x02 for the integer encoding the version) and the
 * version field is marked EXPLICIT in the definition, this makes things
 * pretty simple.
 *
 * version         [0]  EXPLICIT Version DEFAULT v1,
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \initialized(&ctx->version);
  @
  @ assigns *eaten, ctx->version;
  @*/
static int parse_x509_Version(cert_parsing_ctx *ctx,
			      const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	const u8 *buf = cert + off;
	u32 data_len = 0;
	u32 hdr_len = 0;
	int ret;

	if ((cert == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_explicit_id_len(buf, len, 0,
				    CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
				    &hdr_len, &data_len);
	if (ret) {
		ret = X509_PARSER_ERROR_VERSION_ABSENT;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;

	/*
	 * As the value we expect for the integer is 0x02 (version 3),
	 * data_len must be 1.
	 */
	if (data_len != 1) {
		ret = X509_PARSER_ERROR_VERSION_UNEXPECTED_LENGTH;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (buf[0] != 0x02) {
		ret = X509_PARSER_ERROR_VERSION_NOT_3;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->version = buf[0];
	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/*
 * used for SerialNumber (in tbsCertificate or AKI). As the underlying integer
 * might be used with context specific class and types, those two elements are
 * passed to the function and verified to match in given encoding.
 *
 *     CertificateSerialNumber  ::=  INTEGER
 *
 */
#define MAX_SERIAL_NUM_LEN 22 /* w/ header */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_SerialNumber(const u8 *cert, u32 off, u32 len,
			      tag_class exp_class, u32 exp_type,
			      u32 *eaten)
{
	const u8 *buf = cert + off;
	u32 parsed = 0, hdr_len = 0, data_len = 0;
	int ret;

	if ((cert == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* Verify the integer is DER-encoded as it should */
	ret = parse_integer(buf, len, exp_class, exp_type,
			    &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	parsed = hdr_len + data_len;
	/*@ assert parsed > 2; */

	*eaten = parsed;
	/*@ assert *eaten > 2; */

	/*
	 * We now have the guarantee the integer has the following format:
	 * [2 bytes for t/c and len][data_len bytes for encoded value]
	 */

	/*
	 * Serial is expected not to be 0. Because we are guaranteed with the
	 * check above to deal with a DER encoded integer, 0 would be encoded
	 * on exactly 3 bytes (2 for header and 1 for the value), the last one
	 * being 0.
	 */
	if ((data_len == 1) && (buf[2] == 0)) {
#ifndef TEMPORARY_LAXIST_SERIAL_NULL
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
#else
		ret = 0;
#endif
	}

	/*
	 * serialNumber value is expected to be at most 20 bytes long, which
	 * makes 22 bytes for the whole structure (if we include the associated
	 * two bytes header (a length of 20 is encoded on a single byte of
	 * header following the type/class byte.
	 */
	if (parsed > MAX_SERIAL_NUM_LEN) {
#ifndef TEMPORARY_LAXIST_SERIAL_LENGTH
		ret = -__LINE__;
	       ERROR_TRACE_APPEND(__LINE__);
	       goto out;
#else
	       ret = 0;
#endif
	}

	/* ... and be positive */
	if (buf[2] & 0x80) {
#ifndef TEMPORARY_LAXIST_SERIAL_NEGATIVE
		/*
		 * RFC has a MUST (4.1.2.2) for serial integer to
		 * be positive.
		 */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
#else
		/* here, we let it happen */
		ret = 0;
#endif
	}

	ret = 0;

out:
	return ret;
}

/* Specification version for main serial number field of certificate */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \initialized(&ctx->serial_start) && \initialized(&ctx->serial_len);
  @
  @ assigns *eaten, ctx->serial_start, ctx->serial_len;
  @*/
static int parse_CertSerialNumber(cert_parsing_ctx *ctx,
				  const u8 *cert, u32 off, u32 len,
				  tag_class exp_class, u32 exp_type,
				  u32 *eaten)
{
	int ret;

	ret = parse_SerialNumber(cert, off, len, exp_class, exp_type, eaten);
	if (ret) {
	       ERROR_TRACE_APPEND(__LINE__);
	       goto out;
	}

	ctx->serial_start = off + 2; /* 2 bytes long hdr for a valid SN */
	ctx->serial_len = *eaten - 2;

out:
	return ret;
}

/* Specification version for serial number field from AKI */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (2 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_AKICertSerialNumber(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
				     const u8 *cert, u32 off, u32 len,
				     tag_class exp_class, u32 exp_type,
				     u32 *eaten)
{
	int ret;

	ret = parse_SerialNumber(cert, off, len, exp_class, exp_type, eaten);
	if (ret) {
	       ERROR_TRACE_APPEND(__LINE__);
	       goto out;
	}

out:
	return ret;
}

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_HASHES && \result == known_hashes[i] && \valid_read(\result);
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static _hash_alg const * find_hash_by_oid(const u8 *buf, u32 len)
{
	const _hash_alg *found = NULL;
	const _hash_alg *cur = NULL;
	u8 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@ loop unroll NUM_KNOWN_HASHES ;
	  @ loop invariant 0 <= k <= NUM_KNOWN_HASHES;
	  @ loop invariant found == NULL;
	  @ loop invariant (cur != NULL) ==> \valid_read(cur);
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_HASHES - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_HASHES; k++) {
		int ret;

		cur = known_hashes[k];
		/*@ assert \valid_read(cur); */

		/*@ assert cur == known_hashes[k];*/
		if (cur->alg_der_oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->alg_der_oid, buf, cur->alg_der_oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}


/*
 * HashAlgorithm is a sequence containing an OID and parameters which are
 * always NULL for all the hash functions defined in RFC 8017. For that
 * reason, the function only returns a pointer to a known hash alg(from
 * known_hashes) on success (i.e. parameters is useless). The function
 * returns a negative value on error. On success, the length of
 * HashAlgorithm structure is returned.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(hash_alg);
  @ requires \separated(eaten, buf+(..), hash_alg);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (hash_alg == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \exists integer i ; 0 <= i < NUM_KNOWN_HASHES && *hash_alg == known_hashes[i] && \valid_read(*hash_alg);
  @
  @ assigns *eaten, *hash_alg;
  @*/
static int parse_HashAlgorithm(const u8 *buf, u32 len, _hash_alg const **hash_alg,
			       u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0, oid_len = 0, remain = 0;
	int ret;

	if ((buf == NULL) || (hash_alg == NULL) || (eaten == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* We expect a sequence ...  */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	/* ... starting with a hash OID ... */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*hash_alg = find_hash_by_oid(buf, oid_len);
	if (*hash_alg == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \exists integer i ; 0 <= i < NUM_KNOWN_HASHES && *hash_alg == known_hashes[i]; */

	buf += oid_len;
	remain -= oid_len;

	/* ... followed by a NULL ... */
	if ((remain != 2) || (buf[0] != 0x05) || (buf[1] != 0x00)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = hdr_len + data_len;
	ret = 0;

out:
	return ret;
}

/*
 * The function parses the parameters associated with id-RSASSA-PSS
 * OID (1.2.840.113549.1.1.10) found in signature AlgorithmIdentifier
 * The expected structure of the parameters is:
 *
 * RSASSA-PSS-params ::= SEQUENCE {
 *      hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
 *      maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
 *      saltLength         [2] INTEGER            DEFAULT 20,
 *      trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 *  }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((ctx != \null)) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \initialized(&ctx->tbs_sig_alg_oid_params_start) &&
	    \initialized(&ctx->tbs_sig_alg_oid_params_len) &&
	    \initialized(&ctx->hash_alg) &&
	    \initialized(&ctx->sig_alg_params.rsa_ssa_pss.mgf_alg) &&
	    \initialized(&ctx->sig_alg_params.rsa_ssa_pss.mgf_hash_alg) &&
	    \initialized(&ctx->sig_alg_params.rsa_ssa_pss.salt_len) &&
	    \initialized(&ctx->sig_alg_params.rsa_ssa_pss.trailer_field);
  @
  @ assigns ctx->tbs_sig_alg_oid_params_start, ctx->tbs_sig_alg_oid_params_len,
	    ctx->hash_alg, ctx->sig_alg_params.rsa_ssa_pss.mgf_alg,
	    ctx->sig_alg_params.rsa_ssa_pss.mgf_hash_alg,
	    ctx->sig_alg_params.rsa_ssa_pss.salt_len,
	    ctx->sig_alg_params.rsa_ssa_pss.trailer_field;
  @*/
static int parse_algoid_sig_params_rsassa_pss(cert_parsing_ctx *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	u32 remain, hdr_len = 0, data_len = 0, oid_len = 0;
	u32 int_hdr_len = 0, int_data_len = 0;
	u32 attr_hdr_len = 0, attr_data_len = 0, eaten = 0;
	u8 salt_len = 0;
	const u8 *buf = cert + off;
	_hash_alg const *hash = NULL;
	_mgf const *mgf = NULL;
	_hash_alg const *mgf_hash = NULL;
	u8 trailer_field = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * If parsing goes ok, then we will have verified that nothing remains
	 * behind, i.e. that 'len' is indeed the length of the parameters.
	 */
	ctx->tbs_sig_alg_oid_params_start = off;
	ctx->tbs_sig_alg_oid_params_len = len;

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	/*****************************************************************
	 * hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
	 *****************************************************************/
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
			   &attr_hdr_len, &attr_data_len);
	if (ret) {
		/*
		 * hashAlgorithm is missing, which means hash algorithm
		 * to use is the default, i.e. sha1.
		 */
		hash = &_sha1_hash_alg;
	} else {
		buf += attr_hdr_len;
		remain -= attr_hdr_len;

		ret = parse_HashAlgorithm(buf, attr_data_len, &hash, &eaten);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*@ assert \exists integer i ; 0 <= i < NUM_KNOWN_HASHES && hash == known_hashes[i]; */

		/* Verify we have no trailing data */
		if (eaten != attr_data_len) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += eaten;
		remain -= eaten;
	}

	/* Record the hash algorithm we just learnt */
	ctx->hash_alg = hash->hash_id;

	/*****************************************************************
	 * maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,   *
	 *****************************************************************/
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
			   &attr_hdr_len, &attr_data_len);
	if (ret) {
		/*
		 * maskGenAlgorithm is missing, which means MGF
		 * to use is the default, i.e. MGF1 (the only one
		 * defined).
		 */
		mgf = &_mgf1_alg;
		mgf_hash = &_sha1_hash_alg;
	} else {
		buf += attr_hdr_len;
		remain -= attr_hdr_len;

		/* We expect a sequence ...  */
		ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
				   &hdr_len, &data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * Length of the sequence should match data length of attribute,
		 * i.e. we do not accept trailing data
		 */
		if (attr_data_len != (hdr_len + data_len)) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += hdr_len;
		remain -= hdr_len;

		/* ... starting with a MGF OID ... */
		ret = parse_OID(buf, data_len, &oid_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/* Check this is indeed the only OID we support (MGF1 oid). */
		if ((oid_len != _mgf1_alg.alg_der_oid_len) ||
		    bufs_differ(buf, _mgf1_alg.alg_der_oid, oid_len)) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		mgf = &_mgf1_alg;

		buf += oid_len;
		remain -= oid_len;
		data_len -= oid_len;

		/*
		 * ... followed by a HashAlgorithm (a sequence containing a hash
		 * OID and a NULL for associated parameters) ...
		 */
		ret = parse_HashAlgorithm(buf, data_len, &mgf_hash, &eaten);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*@ assert \exists integer i ; 0 <= i < NUM_KNOWN_HASHES && mgf_hash == known_hashes[i]; */

		buf += eaten;
		remain -= eaten;
		data_len -= eaten;

		/* Verify we have no trailing data */
		if (data_len != 0) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

	}

	/* Record the MGF and associated MGF hash alg */
	ctx->sig_alg_params.rsa_ssa_pss.mgf_alg = mgf->mgf_id;
	ctx->sig_alg_params.rsa_ssa_pss.mgf_hash_alg = mgf_hash->hash_id;

	/*****************************************************************
	 * saltLength         [2] INTEGER            DEFAULT 20,         *
	 *****************************************************************/
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 2,
			   &attr_hdr_len, &attr_data_len);
	if (ret) {
		/*
		 * saltLength is missing, which means the default should
		 * be used.
		 */
		salt_len = 20;
	} else {
		buf += attr_hdr_len;
		remain -= attr_hdr_len;

		ret = parse_non_negative_integer(buf, attr_data_len, CLASS_UNIVERSAL,
				ASN1_TYPE_INTEGER, &int_hdr_len,
				&int_data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/* We expect no trailing data */
		eaten = int_hdr_len + int_data_len;
		if (eaten != attr_data_len) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * The spec has no limit on salt length value. As it does not
		 * make sense for salt length to be more than 127 bytes, we
		 * limit integer value to 127, i.e. we expect its value to be
		 * encoded on one byte.
		 */
		if (int_data_len != 1) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		salt_len = buf[2];

		buf += eaten;
		remain -= eaten;
	}

	/* Record the salt_len */
	ctx->sig_alg_params.rsa_ssa_pss.salt_len = salt_len;

	/*****************************************************************
	 * trailerField       [3] TrailerField    DEFAULT trailerFieldBC *
	 *****************************************************************/
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 3,
			   &attr_hdr_len, &attr_data_len);
	if (ret) {
		/*
		 * trailerField is missing, which means the default (0xbc)
		 * should be used.
		 */
		trailer_field = 1; /* indicating 0xbc trailerfield */
	} else {
		/*
		 * The spec only support value 1 for trailerField, which is
		 * the default. Here, the certificate contains an explicit
		 * integer value, which either 1 (same as the default, so
		 * DER makes that invalid) or different (which we do not
		 * support. In both cases, this is invalid. We just go a
		 * bit furtuer in parsing to report a more specific error.
		 */
		buf += attr_hdr_len;
		remain -= attr_hdr_len;

		ret = parse_integer(buf, attr_data_len, CLASS_UNIVERSAL,
				    ASN1_TYPE_INTEGER,
				    &int_hdr_len, &int_data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/* We expect no trailing data */
		eaten = int_hdr_len + int_data_len;
		if (eaten != attr_data_len) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		if (eaten != 3) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		if (buf[2] == 1) {
			/*
			 * This is the default trailer field. DER prevents
			 * explicit setting of the default value
			 */
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * Another value than 1 is also invalid because RFC5280
		 * does not support it
		 */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Record trailer field */
	ctx->sig_alg_params.rsa_ssa_pss.trailer_field = trailer_field;

	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}



/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((ctx != \null)) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->tbs_sig_alg_oid_params_start,
	    ctx->tbs_sig_alg_oid_params_len;
  @*/
static int parse_algoid_sig_params_ecdsa_with(cert_parsing_ctx *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	int ret;

	/*
	 * Based on the OID, specific parameters may follow. As we currently
	 * only support ECDSA-based signature algorithms and RFC5758 specifies
	 * those come w/o any additional parameters, we expect data_len to
	 * exactly match oid_len.
	 *
	 * Section 3.2 of RFC 5758 reads:
	 *
	 *   When the ecdsa-with-SHA224, ecdsa-with-SHA256, ecdsa-with-SHA384,
	 *   or ecdsa-with-SHA512 algorithm identifier appears in the algorithm
	 *   field as an AlgorithmIdentifier, the encoding MUST omit the
	 *   parameters field.  That is, the AlgorithmIdentifier SHALL be a
	 *   SEQUENCE of one component, the OID ecdsa-with-SHA224,
	 *   ecdsa-with-SHA256, ecdsa-with-SHA384, or ecdsa-with-SHA512.
	 *
	 * Section 3 of RFC 8692 defining ECDSA with SHAKE128/256 has the same
	 * requirement.
	 */

	if ((ctx == NULL) || (cert == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
	} else {
		ret = 0;
	}

	ctx->tbs_sig_alg_oid_params_start = off;
	ctx->tbs_sig_alg_oid_params_len = len;

out:
	return ret;
}


/*
 * When Alg OID is 1.2.840.10045.4.3 (ecdsa-with-SHA2), the parameters contains
 * the OID of the hash function to be used with ECDSA for the signature.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((ctx != \null)) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->tbs_sig_alg_oid_params_start,
	    ctx->tbs_sig_alg_oid_params_len,
	    ctx->hash_alg;
  @*/
static int parse_algoid_sig_params_ecdsa_with_specified(cert_parsing_ctx *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	const _hash_alg *hash = NULL;
	u32 parsed = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->tbs_sig_alg_oid_params_start = off;
	ctx->tbs_sig_alg_oid_params_len = len;

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * If parsing goes ok, then we will have verified that nothing remains
	 * behind, i.e. that 'len' is indeed the length of the parameters.
	 */
	ret = parse_HashAlgorithm(buf, len, &hash, &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \exists integer i ; 0 <= i < NUM_KNOWN_HASHES && hash == known_hashes[i]; */

	if (parsed != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Record the hash algorithm we just learnt */
	ctx->hash_alg = hash->hash_id;

out:
	return ret;
}


/*
 * When Alg OID is bign-with-hspec (1.2.112.0.2.0.34.101.45.11), we expect the
 * the parameters to directly contain the OID of the hash function. Nothing else
 * would be valid.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((ctx != \null)) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->tbs_sig_alg_oid_params_start,
	    ctx->tbs_sig_alg_oid_params_len,
	    ctx->hash_alg;
  @*/
static int parse_algoid_sig_params_bign_with_hspec(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	const _hash_alg *hash;
	u32 oid_len = 0;
	u32 remain;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * If parsing goes ok, then we will have verified that nothing remains
	 * behind, i.e. that 'len' is indeed the length of the parameters.
	 */
	ctx->tbs_sig_alg_oid_params_start = off;
	ctx->tbs_sig_alg_oid_params_len = len;

	remain = len;

	/* Let's see if we have on OID here ... */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* ... for a known hash function */
	hash = find_hash_by_oid(buf, oid_len);
	if (hash == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += oid_len;
	remain -= oid_len;

	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Record the hash algorithm we just learnt */
	ctx->hash_alg = hash->hash_id;
	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_CURVES && \result == known_curves[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static _curve const * find_curve_by_oid(const u8 *buf, u32 len)
{
	const _curve *found = NULL;
	const _curve *cur = NULL;
	u8 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@
	  @ loop unroll NUM_KNOWN_CURVES;
	  @ loop invariant 0 <= k <= NUM_KNOWN_CURVES;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_CURVES - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_CURVES; k++) {
		int ret;

		cur = known_curves[k];

		/*@ assert cur == known_curves[k];*/
		if (cur->crv_der_oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->crv_der_oid, buf, cur->crv_der_oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((ctx != \null)) ==> \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len));
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve));
  @
  @ assigns ctx->spki_alg_params.ecpubkey.curve_order_bit_len,
	    ctx->spki_alg_params.ecpubkey.curve;
  @*/
static int parse_algoid_pubkey_params_ecPublicKey(cert_parsing_ctx *ctx,
						  const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	const _curve *curve = NULL;
	u32 oid_len = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Section 2.3.5 of RFC 3279 specifically describe the expected
	 * content of the parameters for ECDSA or ECDH public key embedded
	 * in the subjectPublicKeyInfo of a certificate. Those parameters
	 * follow the OID describing the algotithm in the AlgorithmIdentifier
	 * sequence:
	 *
	 *  AlgorithmIdentifier  ::=  SEQUENCE  {
	 *         algorithm     OBJECT IDENTIFIER,
	 *         parameters    ANY DEFINED BY algorithm OPTIONAL
	 *  }
	 *
	 * Usually, when an AlgorithmIdentifier is used to describe the
	 * signature algorithm in the certificate or the signature
	 * itself, the OID comes with a NULL parameter. But for the
	 * specific OID 1.2.840.10045.2.1 described in Section 2.3.5 of
	 * RFC 3279 to support ECDSA and ECDH public keys in
	 * subjectPublicKeyInfo field, the associated parameters are
	 * expected to be of the following form:
	 *
	 *  EcpkParameters ::= CHOICE {
	 *     ecParameters  ECParameters,
	 *     namedCurve    OBJECT IDENTIFIER,
	 *     implicitlyCA  NULL }
	 *
	 * In practice, to simplify things a lot w/o real lack of
	 * support, we only accept namedCurves (ECParameters is
	 * quite complex and never used in practice), i.e. we
	 * expect to find an OID for a curve we support.
	 */

	if (buf[0] == 0x30) {
		/* Sequence means we are dealing with ecParameters */
		ret = -1;
		goto out;
	}

	/* We should be dealing with a named curve (OID) */
	/* The first thing we should find in the sequence is an OID */
	ret = parse_OID(buf, len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* We do not expected anything after the parameters */
	if (oid_len != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's now see if that OID is one associated w/ a curve we support */
	curve = find_curve_by_oid(buf, oid_len);
	if (curve == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.ecpubkey.curve_order_bit_len = curve->crv_order_bit_len;
	ctx->spki_alg_params.ecpubkey.curve = curve->crv_id;

	ret = 0;

out:
	return ret;
}

/*
 * RFC 8410 defines Agorithm Identifiers for Ed25519 and Ed448
 *
 * subject public key encoding:
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm         AlgorithmIdentifier,
 *      subjectPublicKey  BIT STRING
 * }
 *
 *
 *  The fields in SubjectPublicKeyInfo have the following meanings:
 *
 *  o  algorithm is the algorithm identifier and parameters for the
 *     public key (see above).
 *
 *  o  subjectPublicKey contains the byte stream of the public key.  The
 *     algorithms defined in this document always encode the public key
 *     as an exact multiple of 8 bits.
 *
 * OID are 1.3.101.112 for Ed25519 and 1.3.101.113 for Ed448.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(raw_pub_off);
  @ requires \valid(raw_pub_len);
  @ requires \separated(cert+(..),raw_pub_off, raw_pub_len);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns *raw_pub_off, *raw_pub_len;
  @*/
static int parse_pubkey_eddsa(const u8 *cert, u32 off, u32 len,
			      u32 exp_pub_len, u32 *raw_pub_off, u32 *raw_pub_len)
{
	u32 remain, hdr_len = 0, data_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) ||
	    (raw_pub_off == NULL) || (raw_pub_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* subjectPublicKey field of SubjectPublicKeyInfo is a BIT STRING */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	remain = data_len - 1;

	if (remain != exp_pub_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;
	*raw_pub_off = off + hdr_len + 1;
	*raw_pub_len = exp_pub_len;
out:
	return ret;
}

#define ED25519_PUB_LEN 32
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..),ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.ed25519.ed25519_raw_pub_off,
	    ctx->spki_alg_params.ed25519.ed25519_raw_pub_len;
  @*/
static int parse_pubkey_ed25519(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len)
{
	return parse_pubkey_eddsa(cert, off, len, ED25519_PUB_LEN,
				  &ctx->spki_alg_params.ed25519.ed25519_raw_pub_off,
				  &ctx->spki_alg_params.ed25519.ed25519_raw_pub_len);
}

#define X25519_PUB_LEN ED25519_PUB_LEN
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..),ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.x25519.x25519_raw_pub_off,
	    ctx->spki_alg_params.x25519.x25519_raw_pub_len;
  @*/
static int parse_pubkey_x25519(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len)
{
	return parse_pubkey_eddsa(cert, off, len, X25519_PUB_LEN,
				  &ctx->spki_alg_params.x25519.x25519_raw_pub_off,
				  &ctx->spki_alg_params.x25519.x25519_raw_pub_len);
}

#define ED448_PUB_LEN  57
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..),ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.ed448.ed448_raw_pub_off,
	    ctx->spki_alg_params.ed448.ed448_raw_pub_len;
  @*/
static int parse_pubkey_ed448(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len)
{
	return parse_pubkey_eddsa(cert, off, len, ED448_PUB_LEN,
				  &ctx->spki_alg_params.ed448.ed448_raw_pub_off,
				  &ctx->spki_alg_params.ed448.ed448_raw_pub_len);
}

#define X448_PUB_LEN ED448_PUB_LEN
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..),ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.x448.x448_raw_pub_off,
	    ctx->spki_alg_params.x448.x448_raw_pub_len;
  @*/
static int parse_pubkey_x448(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len)
{
	return parse_pubkey_eddsa(cert, off, len, X448_PUB_LEN,
				  &ctx->spki_alg_params.x448.x448_raw_pub_off,
				  &ctx->spki_alg_params.x448.x448_raw_pub_len);
}

/*
 *  From RFC 3279:
 *
 *  The elliptic curve public key (an ECPoint which is an
 *  OCTET STRING) is mapped to a subjectPublicKey (a BIT
 *  STRING) as follows:  the most significant bit of the
 *  OCTET STRING becomes the most significant bit of the
 *  BIT STRING, and the least significant bit of the OCTET
 *  STRING becomes the least significant bit of the BIT
 *  STRING.
 *
 *  ECPoint ::= OCTET STRING
 *
 *  The value of FieldElement SHALL be the octet string
 *  representation of a field element following the
 *  conversion routine in [X9.62], Section 4.3.3.
 *  The value of ECPoint SHALL be the octet string
 *  representation of an elliptic curve point following
 *  the conversion routine in [X9.62], Section 4.3.6.
 *  Note that this octet string may represent an elliptic
 *  curve point in compressed or uncompressed form.
 *
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..),ctx);
  @ requires \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len));
  @ requires \initialized(&(ctx->spki_alg_params.ecpubkey.curve));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.ecpubkey.compression,
	    ctx->spki_alg_params.ecpubkey.ecc_raw_x_off,
	    ctx->spki_alg_params.ecpubkey.ecc_raw_x_len,
	    ctx->spki_alg_params.ecpubkey.ecc_raw_y_off,
	    ctx->spki_alg_params.ecpubkey.ecc_raw_y_len;
  @*/
static int parse_pubkey_ec(cert_parsing_ctx *ctx,
			   const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	u32 remain;
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 order_ceil_len;
	int ret;
	u8 pc;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* subjectPublicKey field of SubjectPublicKeyInfo is a BIT STRING */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	off += 1;
	remain = data_len - 1;

	/*
	 * From that point on, the parsing of the public key is done as
	 * described in section 4.3.7 of X9.62 version 1998.
	 */

	/*
	 * The first thing we should find is the PC byte, which means
	 * at least one byte should remain at that point.
	 */
	if (remain == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	pc = buf[0];

	remain -= 1;
	buf += 1;
	off += 1;

	/*
	 * We expect a specific length for the remaining data based on
	 * pc byte value.
	 */
	order_ceil_len = (ctx->spki_alg_params.ecpubkey.curve_order_bit_len + 7) / 8;

	switch (pc) {
	case 0x04: /* uncompressed */
		if (remain != (order_ceil_len * 2)) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		ctx->spki_alg_params.ecpubkey.compression = pc;
		ctx->spki_alg_params.ecpubkey.ecc_raw_x_off = off;
		ctx->spki_alg_params.ecpubkey.ecc_raw_x_len = order_ceil_len;
		ctx->spki_alg_params.ecpubkey.ecc_raw_y_off = off + order_ceil_len;
		ctx->spki_alg_params.ecpubkey.ecc_raw_y_len = order_ceil_len;
		break;
	case 0x02: /* compressed point with even y */
	case 0x03: /* compressed point with odd y */
		if (remain != order_ceil_len) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		ctx->spki_alg_params.ecpubkey.compression = pc;
		ctx->spki_alg_params.ecpubkey.ecc_raw_x_off = off;
		ctx->spki_alg_params.ecpubkey.ecc_raw_x_len = order_ceil_len;
		ctx->spki_alg_params.ecpubkey.ecc_raw_y_off = 0;
		ctx->spki_alg_params.ecpubkey.ecc_raw_y_len = 0;
		break;
	default: /* hybrid or other forms: no support */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;
	}

	ret = 0;

out:
	return ret;
}


/*
 * draft-deremin-rfc4491-bis-06 has the following on GOST public keys:
 *
 * The GOST R 34.10-2012 public key MUST be ASN.1 DER encoded as an
 * OCTET STRING.  This encoding SHALL be used as the content (i.e., the
 * value) of the subjectPublicKey field (a BIT STRING) of
 * SubjectPublicKeyInfo structure.
 *
 * GostR3410-2012-256-PublicKey ::= OCTET STRING (64),
 * GostR3410-2012-512-PublicKey ::= OCTET STRING (128).
 *
 * "GostR3410-2012-256-PublicKey" MUST contain 64 octets, where the
 * first 32 octets contain the little-endian representation of "x" and
 * the second 32 octets contains the little-endian representation of "y"
 * coordinates of the public key.
 *
 * "GostR3410-2012-512-PublicKey" MUST contain 128 octets, where the
 * first 64 octets contain the little-endian representation of "x" and
 * the second 64 octets contains the little-endian representation of "y"
 * coordinates of the public key.
 *
 * Note: The format is the same for GOST R 34.10-2001 which has public keys
 * on 256 bit curve, i.e. with a exp_pub_len = 32 * 2 = 64.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(raw_x_off);
  @ requires \valid(raw_x_len);
  @ requires \valid(raw_y_off);
  @ requires \valid(raw_y_len);
  @ requires \separated(cert+(..), raw_x_off, raw_x_len, raw_y_off, raw_y_len);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns *raw_x_off, *raw_x_len, *raw_y_off, *raw_y_len;
  @*/
static int _parse_pubkey_gost_on_curves(const u8 *cert, u32 off, u32 len,
					u32 exp_pub_len,
					u32 *raw_x_off, u32 *raw_x_len,
					u32 *raw_y_off, u32 *raw_y_len)
{
	const u8 *buf = cert + off;
	u32 remain;
	u32 hdr_len = 0;
	u32 data_len = 0;
	int ret;

	if ((cert == NULL) || (len == 0) ||
	    (raw_x_off == NULL) || (raw_x_len == NULL) ||
	    (raw_y_off == NULL) || (raw_y_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	off += hdr_len;
	buf += hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	off += 1;
	remain = data_len - 1;

	/*
	 * We can now consider the content of the bitstring as an ASN.1 octet
	 * string.
	 */
	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (data_len != exp_pub_len) {
		ret = -1;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;

	}

	buf += hdr_len;
	off += hdr_len;
	remain -= hdr_len;

	*raw_x_off = off;
	*raw_x_len = exp_pub_len / 2;
	*raw_y_off = off + *raw_x_len;
	*raw_y_len = exp_pub_len / 2;

	if (remain != data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * RFC 4491 section 2.3.5 has:
 *
 *    The GOST R 34.10-94 public key MUST be ASN.1 DER encoded as an OCTET
 *    STRING; this encoding shall be used as the contents (i.e., the value)
 *    of the subjectPublicKey component (a BIT STRING) of the
 *    SubjectPublicKeyInfo data element.
 *
 *    GostR3410-94-PublicKey ::= OCTET STRING -- public key, Y
 *
 *    GostR3410-94-PublicKey MUST contain 128 octets of the little-endian
 *    representation of the public key Y = a^x (mod p), where a and p are
 *    public key parameters, and x is a private key.
 *
 */
#define GOST94_PUB_LEN 128 /* bytes */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.gost94.gost94_raw_pub_off,
	    ctx->spki_alg_params.gost94.gost94_raw_pub_len;
  @*/
static int parse_pubkey_gostr3410_94(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	u32 remain;
	u32 hdr_len = 0;
	u32 data_len = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	off += hdr_len;
	buf += hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	off += 1;
	remain = data_len - 1;

	/*
	 * We can now consider the content of the bitstring as an ASN.1 octet
	 * string.
	 */
	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (data_len != GOST94_PUB_LEN) {
		ret = -1;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;

	}

	buf += hdr_len;
	off += hdr_len;
	remain -= hdr_len;

	if (remain != data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.gost94.gost94_raw_pub_off = off;
	ctx->spki_alg_params.gost94.gost94_raw_pub_len = GOST94_PUB_LEN;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.gost2001.gost2001_raw_x_pub_off,
	    ctx->spki_alg_params.gost2001.gost2001_raw_x_pub_len,
	    ctx->spki_alg_params.gost2001.gost2001_raw_y_pub_off,
	    ctx->spki_alg_params.gost2001.gost2001_raw_y_pub_len;
  @*/
static inline int parse_pubkey_gostr3410_2001(cert_parsing_ctx *ctx,
				       const u8 *cert, u32 off, u32 len)
{
	return _parse_pubkey_gost_on_curves(cert, off, len, 64,
				 &ctx->spki_alg_params.gost2001.gost2001_raw_x_pub_off,
				 &ctx->spki_alg_params.gost2001.gost2001_raw_x_pub_len,
				 &ctx->spki_alg_params.gost2001.gost2001_raw_y_pub_off,
				 &ctx->spki_alg_params.gost2001.gost2001_raw_y_pub_len);
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.gost2012_256.gost2012_256_raw_x_pub_off,
	    ctx->spki_alg_params.gost2012_256.gost2012_256_raw_x_pub_len,
	    ctx->spki_alg_params.gost2012_256.gost2012_256_raw_y_pub_off,
	    ctx->spki_alg_params.gost2012_256.gost2012_256_raw_y_pub_len;
  @*/
static inline int parse_pubkey_gostr3410_2012_256(cert_parsing_ctx *ctx,
					   const u8 *cert, u32 off, u32 len)
{
	return _parse_pubkey_gost_on_curves(cert, off, len, 64,
				 &ctx->spki_alg_params.gost2012_256.gost2012_256_raw_x_pub_off,
				 &ctx->spki_alg_params.gost2012_256.gost2012_256_raw_x_pub_len,
				 &ctx->spki_alg_params.gost2012_256.gost2012_256_raw_y_pub_off,
				 &ctx->spki_alg_params.gost2012_256.gost2012_256_raw_y_pub_len);
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.gost2012_512.gost2012_512_raw_x_pub_off,
	    ctx->spki_alg_params.gost2012_512.gost2012_512_raw_x_pub_len,
	    ctx->spki_alg_params.gost2012_512.gost2012_512_raw_y_pub_off,
	    ctx->spki_alg_params.gost2012_512.gost2012_512_raw_y_pub_len;
  @*/
static inline int parse_pubkey_gostr3410_2012_512(cert_parsing_ctx *ctx,
				    const u8 *cert, u32 off, u32 len)
{
	return _parse_pubkey_gost_on_curves(cert, off, len, 128,
				 &ctx->spki_alg_params.gost2012_512.gost2012_512_raw_x_pub_off,
				 &ctx->spki_alg_params.gost2012_512.gost2012_512_raw_x_pub_len,
				 &ctx->spki_alg_params.gost2012_512.gost2012_512_raw_y_pub_off,
				 &ctx->spki_alg_params.gost2012_512.gost2012_512_raw_y_pub_len);
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len));
  @ requires \initialized(&(ctx->spki_alg_params.bign.curve));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.bign.bign_raw_x_pub_off,
	    ctx->spki_alg_params.bign.bign_raw_x_pub_len,
	    ctx->spki_alg_params.bign.bign_raw_y_pub_off,
	    ctx->spki_alg_params.bign.bign_raw_y_pub_len;
  @*/
static int parse_pubkey_bign(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
			const u8 *cert, u32 off, u32 len)
{
	u32 order_ceil_len, remain, hdr_len = 0, data_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* subjectPublicKey field of SubjectPublicKeyInfo is a BIT STRING */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	off += 1;
	remain = data_len - 1;

	/*
	 * We expect a specific length for the remaining data based on
	 * pc byte value.
	 */
	order_ceil_len = (ctx->spki_alg_params.bign.curve_order_bit_len + 7) / 8;
	if (remain != (2 * order_ceil_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.bign.bign_raw_x_pub_off = off;
	ctx->spki_alg_params.bign.bign_raw_x_pub_len = order_ceil_len;
	ctx->spki_alg_params.bign.bign_raw_y_pub_off = off + order_ceil_len;
	ctx->spki_alg_params.bign.bign_raw_y_pub_len = order_ceil_len;

	ret = 0;

out:
	return ret;
}

/*
 * When Alg OID is 1.2.112.0.2.0.34.101.45.2.1 (bign-pubkey), the parameters
 * contains an OID for the curve for the public key.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (cert == \null) ==> \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len));
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg_params.bign.curve));
  @
  @ assigns ctx->spki_alg_params.bign.curve_order_bit_len,
	    ctx->spki_alg_params.bign.curve;
  @*/
static int parse_algoid_pubkey_params_bign(cert_parsing_ctx *ctx,
					   const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	const _curve *curve;
	u32 oid_len = 0;
	u32 remain;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	remain = len;
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	curve = find_curve_by_oid(buf, oid_len);
	if (curve == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += oid_len;
	remain -= oid_len;

	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.bign.curve_order_bit_len = curve->crv_order_bit_len;
	ctx->spki_alg_params.bign.curve = curve->crv_id;

	ret = 0;

out:
	return ret;
}


/*
 * When parsing SM2 signature algorithm identifier, we may either find no
 * params or ASN.1 NULL object (SM2 is always used with SM3 hash algorithm).
 * We support those 2 cases we found in real world certs.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->tbs_sig_alg_oid_params_start,
	    ctx->tbs_sig_alg_oid_params_len;
  @*/
static int parse_algoid_sig_params_sm2(cert_parsing_ctx *ctx,
				       const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	u32 parsed = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * If parsing goes ok, then we will have verified that nothing remains
	 * behind, i.e. that 'len' is indeed the length of the parameters.
	 */
	ctx->tbs_sig_alg_oid_params_start = off;
	ctx->tbs_sig_alg_oid_params_len = len;

	switch (len) {
	case 0:
		ret = 0;
		break;
	case 2:
		ret = parse_null(buf, len, &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	default:
		ret = -__LINE__;
		break;
	}

out:
	return ret;
}

/*
 * RFC 8410 has: "For all of the OIDs, the parameters MUST be absent."
 * This is what the function enforces. This applies to both signature
 * parameters and SPKI parameters. We have a specific helper for each
 * case.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len != 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->tbs_sig_alg_oid_params_start,
	    ctx->tbs_sig_alg_oid_params_len;
  @*/
static int parse_algoid_sig_params_eddsa(cert_parsing_ctx *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len != 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->tbs_sig_alg_oid_params_start = off;
	ctx->tbs_sig_alg_oid_params_len = len;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len != 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_oid_params_start,
	    ctx->spki_alg_oid_params_len,
	    ctx->spki_alg_params.ed448.curve,
	    ctx->spki_alg_params.ed448.curve_order_bit_len;
  @*/
static int parse_algoid_pubkey_params_ed448(cert_parsing_ctx *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len != 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_oid_params_start = off;
	ctx->spki_alg_oid_params_len = len;
	ctx->spki_alg_params.ed448.curve = CURVE_WEI448;
	ctx->spki_alg_params.ed448.curve_order_bit_len = 448;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len != 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_oid_params_start,
	    ctx->spki_alg_oid_params_len,
	    ctx->spki_alg_params.x448.curve,
	    ctx->spki_alg_params.x448.curve_order_bit_len;
  @*/
static int parse_algoid_pubkey_params_x448(cert_parsing_ctx *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len != 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_oid_params_start = off;
	ctx->spki_alg_oid_params_len = len;
	ctx->spki_alg_params.x448.curve = CURVE_WEI448;
	ctx->spki_alg_params.x448.curve_order_bit_len = 448;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len != 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_oid_params_start,
	    ctx->spki_alg_oid_params_len,
	    ctx->spki_alg_params.ed25519.curve,
	    ctx->spki_alg_params.ed25519.curve_order_bit_len;
  @*/
static int parse_algoid_pubkey_params_ed25519(cert_parsing_ctx *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len != 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_oid_params_start = off;
	ctx->spki_alg_oid_params_len = len;
	ctx->spki_alg_params.ed25519.curve = CURVE_WEI25519;
	ctx->spki_alg_params.ed25519.curve_order_bit_len = 256;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len != 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_oid_params_start,
	    ctx->spki_alg_oid_params_len,
	    ctx->spki_alg_params.x25519.curve,
	    ctx->spki_alg_params.x25519.curve_order_bit_len;
  @*/
static int parse_algoid_pubkey_params_x25519(cert_parsing_ctx *ctx,
					      const u8 *cert, u32 off, u32 len)
{
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len != 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_oid_params_start = off;
	ctx->spki_alg_oid_params_len = len;
	ctx->spki_alg_params.x25519.curve = CURVE_WEI25519;
	ctx->spki_alg_params.x25519.curve_order_bit_len = 256;

	ret = 0;

out:
	return ret;
}

/*
 * From RFC 5280:
 *
 * subject public key encoding:
 *
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm         AlgorithmIdentifier,
 *      subjectPublicKey  BIT STRING
 * }
 *
 *    AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 * From draft-deremin-rfc4491-bis-06:
 *
 * GOST R 34.10-2012 public keys with 256 bits private key length are
 * identified by the following OID: 1.2.643.7.1.1.1.1
 * GOST R 34.10-2012 public keys with 512 bits private key length are
 * identified by the following OID: 1.2.643.7.1.1.1.2
 *
 * When either of these identifiers appears as algorithm field in
 * SubjectPublicKeyInfo.algorithm.algorithm field, parameters field MUST
 * have the following structure:
 *
 * GostR3410-2012-PublicKeyParameters ::= SEQUENCE {
 *       publicKeyParamSet OBJECT IDENTIFIER,
 *       digestParamSet OBJECT IDENTIFIER OPTIONAL
 * }
 *
 * The function below parses the GostR3410-2012-PublicKeyParameters sequence.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(curve);
  @ requires \valid(hash);
  @ requires \separated(curve, hash, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (hash == \null) ==> \result < 0;
  @ ensures (curve == \null) ==> \result < 0;
  @
  @ assigns *curve, *hash;
  @*/
static int parse_algoid_params_gost2012PublicKey(const u8 *cert, u32 off, u32 len,
						 const _curve **curve, const _hash_alg **hash)
{
	u32 remain, hdr_len = 0, data_len = 0;
	const u8 *buf = cert + off;
	u32 oid_len = 0;
	int ret;

	if ((cert == NULL) || (len == 0) || (curve == NULL) || (hash == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * draft-deremin-rfc4491-bis-06 expects the OID to be in a limited set
	 * defined as:
	 * "public key parameters identifier for GOST R 34.10-2012 (see Sections
	 * 5.1 and 5.2 of [RFC7836] or Appendix B) or GOST R 34.10-2001 (see
	 * Section 8.4 of [RFC4357]) parameters.
	 *
	 * XXX verify that later. At the moment, we accept any valid OID
	 */

	buf += hdr_len;
	remain = data_len;

	/*
	 * The first thing we should find in the sequence is an OID for
	 * publicKeyParamSet
	 */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*curve = find_curve_by_oid(buf, oid_len);
	if (*curve == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += oid_len;
	remain -= oid_len;

	/*
	 * draft-deremin-rfc4491-bis-06 has:
	 *
	 * The field digestParamSet:
	 *
	 * o  SHOULD be omitted if GOST R 34.10-2012 signature algorithm is used
	 *    with 512-bit key length;
	 *
	 * o  MUST be present and must be equal to "id-tc26-digest-
	 *    gost3411-12-256" if one of the following values is used as
	 *    "publicKeyParamSet":
	 *
	 *  "id-GostR3410-2001-CryptoPro-A-ParamSet",
	 *  "id-GostR3410-2001-CryptoPro-B-ParamSet",
	 *  "id-GostR3410-2001-CryptoPro-C-ParamSet",
	 *  "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
	 *  "id-GostR3410-2001-CryptoPro-XchB-ParamSet";
	 *
	 * o  SHOULD be omitted if publicKeyParamSet is equal to:
	 *
	 *  "id-tc26-gost-3410-2012-256-paramSetA";
	 *
	 * o  MUST be omitted if one of the following values is used as
	 *    publicKeyParamSet:
	 *
	 *  "id-tc26-gost-3410-2012-256-paramSetB",
	 *  "id-tc26-gost-3410-2012-256-paramSetC",
	 *  "id-tc26-gost-3410-2012-256-paramSetD".
	 *
	 * XXX At the moment, we just verify we either have nothing following
	 * or a valid OID.
	 */
	if (remain)  {
		/* If something follows, it must be and OID defining digestParamSet. */
		ret = parse_OID(buf, remain, &oid_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		*hash = find_hash_by_oid(buf, oid_len);
		if (*hash == NULL) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += oid_len;
		remain -= oid_len;

		if (remain) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	/*
	 * XXX At that point, we should probably have verified the association of
	 * OID, curves is valid for GOST. This is not done yet
	 */
	ret = 0;

out:
	return ret;
}


/* EA-RSA SPKI algoid optionally contains an integer giving the key size:
 *
 *  See https://www.alvestrand.no/objectid/2.5.8.1.1.html
 *
 * From one cert:
 *
 * 219 156:     SEQUENCE {
 * 222  10:       SEQUENCE {
 * 224   4:         OBJECT IDENTIFIER rsa (2 5 8 1 1)
 * 230   2:         INTEGER 1024
 *        :         }
 * 234 141:       BIT STRING, encapsulates {
 * 238 137:         SEQUENCE {
 * 241 129:           INTEGER
 *        :             00 84 89 E4 7C 35 C5 E4 51 6D 5F D0 6E 9A 0B AB
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_params.rsa.rsa_advertised_bit_len;
  @*/
static int parse_algoid_pubkey_params_ea_rsa(cert_parsing_ctx *ctx,
					     const u8 *cert, u32 off, u32 len)
{
	u32 hdr_len = 0, data_len = 0;
	const u8 *buf = cert + off;
	u32 bit_len = 0, parsed = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert (len > 0) ==> \valid_read(buf + (0 .. len - 1)); */

	/*
	 * We can either find nothing, a NULL or an integer with the bit size
	 * of the key.
	 */
	switch (len) {
	case 0: /* nothing */
		ret = 0;
		break;

	case 2: /* NULL */
		ret = parse_null(buf, len, &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		break;

	case 4: /* Integer */
		/*
		 * Having a RSA key with a bit length value below 127 and above
		 * 32768 does not make sense. For that reason, we expected the
		 * integer to be encoded on 4 bytes: 1 for class/id, 1 for
		 * length, 2 for integer value
		 */

		/* Verify the integer is DER-encoded as it should */
		ret = parse_non_negative_integer(buf, len, CLASS_UNIVERSAL,
					     ASN1_TYPE_INTEGER,
					     &hdr_len, &data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		bit_len = ((u32)buf[2] << 8) + (u32)buf[3];

		break;

	default:
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		break;
	}

	ctx->spki_alg_params.rsa.rsa_advertised_bit_len = bit_len;

out:
	return ret;
}

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_GOST94_PARAMS && \result == known_gost_94_params[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static const _gost94_pub_params * find_gost94_params_by_oid(const u8 *buf, u32 len)
{
	const _gost94_pub_params *found = NULL;
	const _gost94_pub_params *cur = NULL;
	u8 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@
	  @ loop invariant 0 <= k <= NUM_KNOWN_GOST94_PARAMS;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_GOST94_PARAMS - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_GOST94_PARAMS; k++) {
		int ret;

		cur = known_gost_94_params[k];

		/*@ assert cur == known_gost_94_params[k];*/
		if (cur->params_der_oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->params_der_oid, buf, cur->params_der_oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}


/*
 * RFC 4491, RFC 4357
 *
 * Section 2.3.1 of RFC 4491 has:
 *
 *  GostR3410-94-PublicKeyParameters ::=
 *         SEQUENCE {
 *             publicKeyParamSet
 *                 OBJECT IDENTIFIER,
 *             digestParamSet
 *                 OBJECT IDENTIFIER,
 *             encryptionParamSet
 *                 OBJECT IDENTIFIER DEFAULT
 *                     id-Gost28147-89-CryptoPro-A-ParamSet
 *         }
 *
 * In the certificate we have at hand, we only have the first 2 OIDs and the
 * optional is not there e.g.
 *
 * 3012 06072a850302022002 06072a850302021e01
 *
 * i.e. a sequence of 2 OIDs:
 *
 * 06072a850302022002  1.2.643.2.2.32.2   id-GostR3410-94-CryptoPro-A-ParamSet
 * 06072a850302021e01  1.2.643.2.2.30.1   GOST R 3411-94 CryptoProParamSet
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_params.gost94.gost94_params_id;
  @*/
static int parse_algoid_pubkey_params_gost_r3410_94(cert_parsing_ctx *ctx,
						   const u8 *cert, u32 off, u32 len)
{
	u32 remain, hdr_len = 0, data_len = 0, oid_len = 0;
	const _gost94_pub_params *params;
	const u8 *buf = cert + off;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* We expect a sequence ...  */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	/* ... starting with a first OID for GOST R 34.10-94 paramset */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	params = find_gost94_params_by_oid(buf, oid_len);
	if (params == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	ctx->spki_alg_params.gost94.gost94_params_id = params->params_id;

	buf += oid_len;
	remain -= oid_len;

	/* ... followed by a second OID for GOST R 34.11-94 paramset */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * XXX at some point we could create a list of known paramset
	 * and associated OID as defined in section 8.3. of RFC 4357
	 */

	buf += oid_len;
	remain -= oid_len;

	/* Let's verify we have nothing left behind */
	if (remain) {
		/* We may have an optional encryptionParamset */
		ret = parse_OID(buf, remain, &oid_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= oid_len;

		if (remain) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	ret = 0;

out:
	return ret;

}

/*
 * Used for parsing AlgorithmIdentifiter parameters for GOST R3410-2001 public
 * key. As described in RFC 4491:
 *
 *  When the id-GostR3410-2001 algorithm identifier appears as the algorithm
 *  field in an AlgorithmIdentifier, the encoding MAY omit the parameters field
 *  or set it to NULL.  Otherwise, this field MUST have the following structure:
 *
 *     GostR3410-2001-PublicKeyParameters ::=
 *         SEQUENCE {
 *             publicKeyParamSet
 *                 OBJECT IDENTIFIER,
 *             digestParamSet
 *                 OBJECT IDENTIFIER,
 *             encryptionParamSet
 *                 OBJECT IDENTIFIER DEFAULT
 *                     id-Gost28147-89-CryptoPro-A-ParamSet
 *         }
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_params.gost2001.curve_order_bit_len,
	    ctx->spki_alg_params.gost2001.curve;
  @*/
static int parse_algoid_pubkey_params_gost_r3410_2001(cert_parsing_ctx *ctx,
						      const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	u32 remain, hdr_len = 0, data_len = 0;
	const _curve *curve;
	const _hash_alg *h;
	u32 parsed = 0;
	u32 oid_len = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len == 0) { /* the encoding MAY omit the parameters field ... */
		ret = 0;
		goto out;
	}

	if (len == 2 && !parse_null(buf, len, &parsed)) { /* or set it to NULL */
		ret = 0;
		goto out;
	}

	/*
	 * From now on, we expect a gostR3410-2001-PublicKeyParameters as
	 * defined above. It must start with a valid sequence.
	 */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	/*
	 * The first thing we should find in the sequence is an OID for
	 * publicKeyParamSet
	 */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	curve = find_curve_by_oid(buf, oid_len);
	if (curve == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += oid_len;
	remain -= oid_len;

	/* Then, we may  find an OID for digestParamSet. It is not optional */
	/* If something follows, it must be and OID defining digestParamSet. */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	h = find_hash_by_oid(buf, oid_len);
	if (h == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += oid_len;
	remain -= oid_len;

	if (remain)  {
		/* Something follows. This must be the OID for encryptionParamSet. */
		ret = parse_OID(buf, remain, &oid_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += oid_len;
		remain -= oid_len;

		/* Nothings should remain behind */
		if (remain) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	ctx->spki_alg_params.gost2001.curve_order_bit_len = curve->crv_order_bit_len;
	ctx->spki_alg_params.gost2001.curve = curve->crv_id;
	// XXX investigate hash hash->hash_id purpose for pubkey

	ret = 0;

out:
	return ret;
}

/*
 * Used for parsing AlgorithmIdentifiter parameters for GOST R3410-2001 with 256
 * bits public key
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_params.gost2012_256.curve_order_bit_len,
	    ctx->spki_alg_params.gost2012_256.curve;
  @*/
static int parse_algoid_pubkey_params_gost_r3410_2012_256(cert_parsing_ctx *ctx,
							  const u8 *cert, u32 off, u32 len)
{
	const _hash_alg *hash = NULL;
	const _curve *curve = NULL;
	int ret;

	if ((ctx == NULL) || (cert == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_algoid_params_gost2012PublicKey(cert, off, len, &curve, &hash);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (curve == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.gost2012_256.curve_order_bit_len = curve->crv_order_bit_len;
	ctx->spki_alg_params.gost2012_256.curve = curve->crv_id;
	// investiage hash hash->hash_id purpose for pubkey

out:

	return ret;
}

/*
 * Used for parsing AlgorithmIdentifiter parameters for GOST R3410-2012 with 512
 * bit public key.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_params.gost2012_512.curve_order_bit_len,
	    ctx->spki_alg_params.gost2012_256.curve;
  @*/
static int parse_algoid_pubkey_params_gost_r3410_2012_512(cert_parsing_ctx *ctx,
							  const u8 *cert, u32 off, u32 len)
{
	const _hash_alg *hash = NULL;
	const _curve *curve = NULL;
	int ret;

	if (ctx == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_algoid_params_gost2012PublicKey(cert, off, len, &curve, &hash);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (curve == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.gost2012_512.curve_order_bit_len = curve->crv_order_bit_len;
	ctx->spki_alg_params.gost2012_256.curve = curve->crv_id;
	// XXX investigate hash hash->hash_id purpose for pubkey

out:
	return ret;
}

/*
 * Handles expected lack of optinal parameters associated with sig and pubkey
 * OID. The function also support the case where lack of parames has been
 * implemented by some software by a adding a NULL instead of nothing.
 * We define specific sig and pubky function from that one below.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int _parse_algoid_params_none(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	u32 parsed = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert (len > 0) ==> \valid_read(buf + (0 .. len - 1)); */

	switch (len) {
	case 0: /* Nice ! */
		ret = 0;
		break;
	case 2: /* Null ? */
		ret = parse_null(buf, len, &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	default: /* Crap ! */
		ret = -1;
		ERROR_TRACE_APPEND(__LINE__);
		break;
	}

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->tbs_sig_alg_oid_params_start,
	    ctx->tbs_sig_alg_oid_params_len;
  @*/
static int parse_algoid_sig_params_none(cert_parsing_ctx *ctx,
					const u8 *cert, u32 off, u32 len)
{
	int ret;

	ret = _parse_algoid_params_none(ctx, cert, off, len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->tbs_sig_alg_oid_params_start = off;
	ctx->tbs_sig_alg_oid_params_len = len;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_oid_params_start,
	    ctx->spki_alg_oid_params_len;
  @*/
static int parse_algoid_pubkey_params_none(cert_parsing_ctx *ctx,
					   const u8 *cert, u32 off, u32 len)
{
	int ret;

	ret = _parse_algoid_params_none(ctx, cert, off, len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_oid_params_start = off;
	ctx->spki_alg_oid_params_len = len;

out:
	return ret;
}


/*
 * Parser for parameters associated with the OID for RSA public key
 * (rsaEncryption, GIP-CPS, ) and common PKCS#1 v1.5 signature OID
 * (sha*WithRSAEncryption, md5WithRSAEncryption).
 * Those all expect a NULL parameter. From this function,
 * we define specific instances for signature and pubkey parameters
 * below.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns \nothing;
  @*/
static int _parse_algoid_params_rsa(cert_parsing_ctx *ctx,
				    const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	u32 parsed = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert (len > 0) ==> \valid_read(buf + (0 .. len - 1)); */

#ifdef TEMPORARY_LAXIST_RSA_PUBKEY_AND_SIG_NO_PARAMS_INSTEAD_OF_NULL
	/*
	 * We expect a null but will allow empty params
	 * in that case.
	 */
	if (len == 0) {
		ret = 0;
		goto out;
	}
#endif
	/*
	 * Section 3.2 of RFC 3370 explicitly states that
	 * "When the rsaEncryption, sha1WithRSAEncryption, or
	 * md5WithRSAEncryption signature value algorithm
	 * identifiers are used, the AlgorithmIdentifier parameters
	 * field MUST be NULL.", i.e. contain { 0x05, 0x00 }
	 *
	 */
	ret = parse_null(buf, len, &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->tbs_sig_alg_oid_params_start,
	    ctx->tbs_sig_alg_oid_params_len;
  @*/
static int parse_algoid_sig_params_rsa(cert_parsing_ctx *ctx,
				       const u8 *cert, u32 off, u32 len)
{
	int ret;

	ret = _parse_algoid_params_rsa(ctx, cert, off, len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->tbs_sig_alg_oid_params_start = off;
	ctx->tbs_sig_alg_oid_params_len = len;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_oid_params_start,
	    ctx->spki_alg_oid_params_len;
  @*/
static int parse_algoid_pubkey_params_rsa(cert_parsing_ctx *ctx,
					const u8 *cert, u32 off, u32 len)
{
	int ret;

	ret = _parse_algoid_params_rsa(ctx, cert, off, len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_oid_params_start = off;
	ctx->spki_alg_oid_params_len = len;

out:
	return ret;
}

/*
 * From RFC 3279:
 *
 * The RSA public key MUST be encoded using the ASN.1
 * type RSAPublicKey:
 *
 * RSAPublicKey ::= SEQUENCE {
 *  modulus            INTEGER,    -- n
 *  publicExponent     INTEGER  }  -- e
 *
 * where modulus is the modulus n, and publicExponent
 * is the public exponent e. The DER encoded
 * RSAPublicKey is the value of the BIT STRING
 * subjectPublicKey.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(n_start_off);
  @ requires \valid(n_len);
  @ requires \valid(e_start_off);
  @ requires \valid(e_len);
  @ requires \separated(buf+(..), n_start_off, n_len, e_start_off, e_len);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> (u64)*n_start_off + (u64)*n_len <= (u64)len;
  @ ensures (\result == 0) ==> (u64)*e_start_off + (u64)*e_len <= (u64)len;
  @
  @ assigns *n_start_off, *n_len, *e_start_off, *e_len;
  @*/
static int spki_rsa_export_n_e(const u8 *buf, u32 len,
			       u32 *n_start_off, u32 *n_len,
			       u32 *e_start_off, u32 *e_len)
{
	u32 remain;
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 parsed = 0;
	u32 off;
	int ret;

	if ((buf == NULL) || (len == 0) ||
	    (n_start_off == NULL) || (n_len == NULL) ||
	    (e_start_off == NULL) || (e_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* subjectPublicKey field of SubjectPublicKeyInfo is a BIT STRING */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off = hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	remain = data_len - 1;
	off += 1;

	/*
	 * Now, in the case of a RSA public key, we expect the content of
	 * the BIT STRING to contain a SEQUENCE of two INTEGERS
	 */
	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;
	off += hdr_len;

	/*
	 * Now, we should find the first integer, n (modulus). We first parse
	 * it to validate it. Then, we skip over the header to move to get up
	 * to the position of the modulus
	 */
	ret = parse_non_negative_integer(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
				     &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	parsed = hdr_len + data_len;

	/*@ assert ((u64)hdr_len + (u64)data_len) <= (u64)remain; */
	/*@ assert remain <= len; */
	/*@ assert (u64)off + (u64)hdr_len + (u64)data_len <= (u64)len; */
	*n_start_off = off + hdr_len;
	*n_len = data_len;
	/*@ assert (u64)*n_start_off + (u64)*n_len <= (u64)len; */

	/* if MSB of modulus is 0, remove it */
	if ((data_len != 0) && (buf[hdr_len] == 0)) {
		*n_start_off += 1;
		*n_len -= 1;
	}

	buf += parsed;
	off += parsed;
	remain -= parsed;

	/* An then, the second one, e (publicExponent) */
	ret = parse_non_negative_integer(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
				     &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	parsed = hdr_len + data_len;

	/*@ assert ((u64)hdr_len + (u64)data_len) <= (u64)remain; */
	/*@ assert remain <= len; */
	/*@ assert (u64)off + (u64)hdr_len + (u64)data_len <= (u64)len; */
	*e_start_off = off + hdr_len;
	*e_len = data_len;
	/*@ assert (u64)*e_start_off + (u64)*e_len <= (u64)len; */

	buf += parsed;
	off += parsed;
	remain -= parsed;

	if (remain != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns ctx->spki_alg_params.rsa.rsa_raw_modulus_off,
	    ctx->spki_alg_params.rsa.rsa_raw_modulus_len,
	    ctx->spki_alg_params.rsa.rsa_raw_pub_exp_off,
	    ctx->spki_alg_params.rsa.rsa_raw_pub_exp_len;
  @*/
static int parse_pubkey_rsa(cert_parsing_ctx *ctx,
			    const u8 *cert, u32 off, u32 len)
{
	u32 n_start_off = 0, n_len = 0, e_start_off= 0, e_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = spki_rsa_export_n_e(buf, len, &n_start_off, &n_len, &e_start_off, &e_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.rsa.rsa_raw_modulus_off = off + n_start_off;
	ctx->spki_alg_params.rsa.rsa_raw_modulus_len = n_len;
	ctx->spki_alg_params.rsa.rsa_raw_pub_exp_off = off + e_start_off;
	ctx->spki_alg_params.rsa.rsa_raw_pub_exp_len = e_len;

out:
	return ret;
}

/*
 * Section 7.3.3 of RFC 2459 has:
 *
 *   If the DSA algorithm parameters are present in the
 *   subjectPublicKeyInfo AlgorithmIdentifier, the parameters are included
 *   using the following ASN.1 structure:
 *
 *        Dss-Parms  ::=  SEQUENCE  {
 *            p             INTEGER,
 *            q             INTEGER,
 *            g             INTEGER  }
 *
 *
 *   If the DSA algorithm parameters are absent from the
 *   subjectPublicKeyInfo AlgorithmIdentifier and the CA signed the
 *   subject certificate using DSA, then the certificate issuer's DSA
 *   parameters apply to the subject's DSA key.  If the DSA algorithm
 *   parameters are absent from the subjectPublicKeyInfo
 *   AlgorithmIdentifier and the CA signed the subject certificate using a
 *   signature algorithm other than DSA, then the subject's DSA parameters
 *   are distributed by other means.  If the subjectPublicKeyInfo
 *   AlgorithmIdentifier field omits the parameters component and the CA
 *   signed the subject with a signature algorithm other than DSA, then
 *   clients shall reject the certificate.
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(p_start_off);
  @ requires \valid(p_len);
  @ requires \valid(q_start_off);
  @ requires \valid(q_len);
  @ requires \valid(g_start_off);
  @ requires \valid(g_len);
  @ requires \separated(buf+(..), p_start_off, p_len, q_start_off, q_len, g_start_off, g_len);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (p_start_off == \null) ==> \result < 0;
  @ ensures (p_len == \null) ==> \result < 0;
  @ ensures (q_start_off == \null) ==> \result < 0;
  @ ensures (q_len == \null) ==> \result < 0;
  @ ensures (g_start_off == \null) ==> \result < 0;
  @ ensures (g_len == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> *p_start_off <= len;
  @ ensures (\result == 0) ==> *q_start_off <= len;
  @ ensures (\result == 0) ==> *g_start_off <= len;
  @ ensures (\result == 0) ==> (u64)*p_start_off + (u64)*p_len <= (u64)len;
  @ ensures (\result == 0) ==> (u64)*q_start_off + (u64)*q_len <= (u64)len;
  @ ensures (\result == 0) ==> (u64)*g_start_off + (u64)*g_len <= (u64)len;
  @
  @ assigns *p_start_off, *p_len, *q_start_off, *q_len, *g_start_off, *g_len;
  @*/
int parse_algoid_dsa_export_params(const u8 *buf, u32 len,
				   u32 *p_start_off, u32 *p_len,
				   u32 *q_start_off, u32 *q_len,
				   u32 *g_start_off, u32 *g_len)
{
	u32 remain = 0;
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 eaten = 0;
	u32 parsed = 0;
	u32 off = 0;
	int ret;

	if ((buf == NULL) ||
	    (p_start_off == NULL) || (p_len == NULL) ||
	    (q_start_off == NULL) || (q_len == NULL) ||
	    (g_start_off == NULL) || (g_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*p_start_off = 0;
	*p_len = 0;
	*q_start_off = 0;
	*q_len = 0;
	*g_start_off = 0;
	*g_len = 0;

	/*
	 * It is acceptable for DSA params to be absent (i.e. null or nothing
	 * at all aka zero length), as explained in RFC description
	 */
	if (len == 0) {
		ret = 0;
		goto out;
	}

	ret = parse_null(buf, len, &parsed);
	if (!ret) {
		ret = 0;
		goto out;
	}

	/*
	 * If not absent, params are expected to contain a sequence of
	 * 3 integers p, q and s.
	 *
	 *         Dss-Parms  ::=  SEQUENCE  {
	 *            p             INTEGER,      -- DSA prime
	 *            q             INTEGER,      -- DSA group order
	 *            g             INTEGER  }    -- DSA group generator
	 */
	remain = len;
	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	/* Now, we should find the first integer, p, the DSA prime */
	ret = parse_non_negative_integer(buf, remain, CLASS_UNIVERSAL,
					 ASN1_TYPE_INTEGER,
					 &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	eaten = hdr_len + data_len;

	*p_start_off = off + hdr_len;
	*p_len = data_len;

	remain -= eaten;
	buf += eaten;
	off += eaten;

	/* An then, the second one, q, the DSA group order */
	ret = parse_non_negative_integer(buf, remain, CLASS_UNIVERSAL,
					 ASN1_TYPE_INTEGER,
					 &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	eaten = hdr_len + data_len;

	*q_start_off = off + hdr_len;
	*q_len = data_len;

	remain -= eaten;
	buf += eaten;
	off += eaten;

	/* An in the end, the third one, g, the group genrator */
	ret = parse_non_negative_integer(buf, remain, CLASS_UNIVERSAL,
					 ASN1_TYPE_INTEGER,
					 &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	eaten = hdr_len + data_len;

	*g_start_off = off + hdr_len;
	*g_len = data_len;
	remain -= eaten;

	/* Let's check that nothing remains behind */
	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}



/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns ctx->spki_alg_params.dsa.dsa_raw_p_off,
	    ctx->spki_alg_params.dsa.dsa_raw_p_len,
	    ctx->spki_alg_params.dsa.dsa_raw_q_off,
	    ctx->spki_alg_params.dsa.dsa_raw_q_len,
	    ctx->spki_alg_params.dsa.dsa_raw_g_off,
	    ctx->spki_alg_params.dsa.dsa_raw_g_len;
  @*/
static int parse_algoid_pubkey_params_dsa(cert_parsing_ctx *ctx,
					  const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	u32 p_start_off, p_len;
	u32 q_start_off, q_len;
	u32 g_start_off, g_len;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_algoid_dsa_export_params(buf, len,
					     &p_start_off, &p_len,
					     &q_start_off, &q_len,
					     &g_start_off, &g_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.dsa.dsa_raw_p_off = off + p_start_off;
	ctx->spki_alg_params.dsa.dsa_raw_p_len = p_len;
	ctx->spki_alg_params.dsa.dsa_raw_q_off = off + q_start_off;
	ctx->spki_alg_params.dsa.dsa_raw_q_len = q_len;
	ctx->spki_alg_params.dsa.dsa_raw_g_off = off + g_start_off;
	ctx->spki_alg_params.dsa.dsa_raw_g_len = g_len;

out:
	return ret;
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(pub_start_off);
  @ requires \valid(pub_len);
  @ requires \separated(buf+(..), pub_start_off, pub_len);
  @
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> *pub_start_off <= len;
  @ ensures (\result == 0) ==> (u64)*pub_start_off + (u64)*pub_len <= (u64)len;
  @
  @ assigns *pub_start_off, *pub_len;
  @*/
int parse_pubkey_dsa_export_pub(const u8 *buf, u32 len,
				u32 *pub_start_off, u32 *pub_len)
{
	u32 remain;
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 off;
	int ret;

	if ((buf == NULL) || (len == 0) ||
	    (pub_start_off == NULL) || (pub_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* subjectPublicKey field of SubjectPublicKeyInfo is a BIT STRING */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off = hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	remain = data_len - 1;
	off += 1;

	/*
	 * Now, in the case of a DSA public key, we expect the content of
	 * the BIT STRING to hold an INTEGER
	 */
	ret = parse_non_negative_integer(buf, remain, CLASS_UNIVERSAL,
					 ASN1_TYPE_INTEGER,
					 &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;
	off += hdr_len;
	*pub_start_off = off;
	*pub_len = data_len;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \separated(cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns *ctx;
  @*/
static int parse_pubkey_dsa(cert_parsing_ctx *ctx,
			    const u8 *cert, u32 off, u32 len)
{
	const u8 *buf = cert + off;
	u32 pub_start_off = 0, pub_len = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert (len >= 0) ==> \valid_read(buf + (0 .. len - 1)); */

	ret = parse_pubkey_dsa_export_pub(buf, len, &pub_start_off, &pub_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_alg_params.dsa.dsa_raw_pub_off = off + pub_start_off;
	ctx->spki_alg_params.dsa.dsa_raw_pub_len = pub_len;

out:
	return ret;
}


/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_SIG_ALGS && \result == known_sig_algs[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static const _sig_alg * find_sig_alg_by_oid(const u8 *buf, u32 len)
{
	const _sig_alg *found = NULL;
	const _sig_alg *cur = NULL;
	u8 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@
	  @ loop unroll NUM_KNOWN_SIG_ALGS;
	  @ loop invariant 0 <= k <= NUM_KNOWN_SIG_ALGS;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_SIG_ALGS - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_SIG_ALGS; k++) {
		int ret;

		cur = known_sig_algs[k];

		/*@ assert cur == known_sig_algs[k]; */
		if (cur->alg_der_oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->alg_der_oid, buf, cur->alg_der_oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}


/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_PUBKEY_ALGS && \result == known_pubkey_algs[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static const _pubkey_alg * find_pubkey_alg_by_oid(const u8 *buf, u32 len)
{
	const _pubkey_alg *found = NULL;
	const _pubkey_alg *cur = NULL;
	u8 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@ loop unroll NUM_KNOWN_PUBKEY_ALGS;
	  @ loop invariant 0 <= k <= NUM_KNOWN_PUBKEY_ALGS;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_PUBKEY_ALGS - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_PUBKEY_ALGS; k++) {
		int ret;

		cur = known_pubkey_algs[k];

		/*@ assert cur == known_pubkey_algs[k]; */
		if (cur->alg_der_oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->alg_der_oid, buf, cur->alg_der_oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}


/*
 * The algorithmIdentifier structure is used at different location
 * in a certificate for different kind of algorithms:
 *
 *  - in signature and signatureAlgorithm fields, it describes a
 *    signature algorithm.
 *  - in subjectPublicKeyInfo, it describes a public key
 *    algorithm.
 *
 * It has the following structure:
 *
 * AlgorithmIdentifier. Used for signature field.
 *
 *    AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 * In the parser, we define currently define two functions:
 *
 *  - one for parsing tbsCertificate.signature algoid field
 *  - one for parsing spki algoid field
 *
 * Parsing of certificate signatureAlgorithm field is not performed.
 * as it must exactly match the content of tbsCertificate.signature
 * field. A simple comparison is performed for that purpose.
 */

/*
 * This function parses tbsCertificate.signature field and populate ctx with useful
 * information on success.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \valid(alg);
  @ requires \valid(eaten);
  @ requires \separated(cert+(..),alg,ctx,eaten);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> \exists integer x; 0 <= x < NUM_KNOWN_SIG_ALGS && *alg == known_sig_algs[x];
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \valid_read(*alg);
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_oid_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_oid_len));
  @ ensures (\result == 0) ==> \initialized(&(ctx->sig_alg));
  @ ensures (\result == 0) ==> \initialized(&(ctx->hash_alg));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_start));
  @ ensures (\result == 0) ==> ctx->tbs_sig_alg_start == off;
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_len));
  @
  @ assigns *alg, *eaten, *ctx;
  @*/
static int parse_x509_tbsCert_sig_AlgorithmIdentifier(cert_parsing_ctx *ctx,
						      const u8 *cert, u32 off, u32 len,
						      const _sig_alg **alg,
						      u32 *eaten)
{
	const _sig_alg *talg = NULL;
	const u8 *buf = cert + off;
	u32 saved_off = off;
	u32 parsed = 0;
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 param_len;
	u32 oid_len = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	parsed = hdr_len + data_len;
	/*@ assert (1 < parsed <= len); */

	buf += hdr_len;
	off += hdr_len;

	/* The first thing we should find in the sequence is an OID */
	ret = parse_OID(buf, data_len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's now see if that OID is one associated w/ an alg we support */
	talg = find_sig_alg_by_oid(buf, oid_len);
	if (talg == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert \valid_read(talg); */
	/*@ assert \exists integer i ; 0 <= i < NUM_KNOWN_SIG_ALGS && talg == known_sig_algs[i]; */

	/*
	 * Record position of spki alg oid. Also keep track of
	 * the signature mechanism alg identifier and possibly
	 * the associated hash identifier if it was explicit in
	 * the mechanism. Otherwise, we will temporarily inherit
	 * from HASH_ALG_UNKNOWN and possibly get the hash during
	 * the parsing of alg oid sig parameters just below.
	 */
	ctx->tbs_sig_alg_oid_start = off;
	ctx->tbs_sig_alg_oid_len = oid_len;
	ctx->sig_alg = talg->sig_id;
	ctx->hash_alg = talg->hash_id;

	buf += oid_len;
	off += oid_len;
	param_len = data_len - oid_len;

	/*@ assert talg->parse_algoid_sig_params \in {
		  parse_algoid_sig_params_ecdsa_with,
		  parse_algoid_sig_params_ecdsa_with_specified,
		  parse_algoid_sig_params_sm2,
		  parse_algoid_sig_params_eddsa,
		  parse_algoid_sig_params_rsa,
		  parse_algoid_sig_params_rsassa_pss,
		  parse_algoid_sig_params_none,
		  parse_algoid_sig_params_bign_with_hspec }; @*/
	/*@ calls parse_algoid_sig_params_ecdsa_with,
		  parse_algoid_sig_params_ecdsa_with_specified,
		  parse_algoid_sig_params_sm2,
		  parse_algoid_sig_params_eddsa,
		  parse_algoid_sig_params_rsa,
		  parse_algoid_sig_params_rsassa_pss,
		  parse_algoid_sig_params_none,
		  parse_algoid_sig_params_bign_with_hspec; @*/
	ret = talg->parse_algoid_sig_params(ctx, cert, off, param_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \exists integer i ; 0 <= i < NUM_KNOWN_SIG_ALGS && talg == known_sig_algs[i]; */
	*alg = talg;
	*eaten = parsed;
	ctx->tbs_sig_alg_start = saved_off;
	ctx->tbs_sig_alg_len = parsed;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(alg);
  @ requires \separated(cert+(..),alg,eaten,ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> \exists u8 x; *alg == known_pubkey_algs[x];
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> \valid_read(*alg);
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg));
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg_oid_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->spki_alg_oid_len));
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len));
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve));
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len));
  @ ensures (\result == 0) && (*alg)->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve));
  @
  @ assigns *alg, *eaten, *ctx;
  @*/
static int parse_x509_pubkey_AlgorithmIdentifier(cert_parsing_ctx *ctx,
						 const u8 *cert, u32 off, u32 len,
						 const _pubkey_alg **alg,
						 u32 *eaten)
{
	const _pubkey_alg *talg = NULL;
	const u8 *buf = cert + off;
	u32 saved_off = off;
	u32 parsed = 0;
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 param_len;
	u32 oid_len = 0;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;

	/* The first thing we should find in the sequence is an OID */
	ret = parse_OID(buf, data_len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* record position of spki alg oid */
	ctx->spki_alg_oid_start = off;
	ctx->spki_alg_oid_len = oid_len;

	/* Let's see if that OID is one associated w/ a pubkey alg we support */
	talg = find_pubkey_alg_by_oid(buf, oid_len);
	if (talg == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert \valid_read(talg); */

	buf += oid_len;
	off += oid_len;
	param_len = data_len - oid_len;

	/*@ assert talg->parse_algoid_pubkey_params \in {
		   parse_algoid_pubkey_params_ecPublicKey,
		   parse_algoid_pubkey_params_ed25519,
		   parse_algoid_pubkey_params_ed448,
		   parse_algoid_pubkey_params_x25519,
		   parse_algoid_pubkey_params_x448,
		   parse_algoid_pubkey_params_rsa,
		   parse_algoid_pubkey_params_gost_r3410_2012_256,
		   parse_algoid_pubkey_params_gost_r3410_2012_512,
		   parse_algoid_pubkey_params_gost_r3410_2001,
		   parse_algoid_pubkey_params_gost_r3410_94,
		   parse_algoid_pubkey_params_dsa,
		   parse_algoid_pubkey_params_ea_rsa,
		   parse_algoid_pubkey_params_none,
		   parse_algoid_pubkey_params_bign}; @*/
	/*@ calls parse_algoid_pubkey_params_ecPublicKey,
		   parse_algoid_pubkey_params_ed25519,
		   parse_algoid_pubkey_params_ed448,
		   parse_algoid_pubkey_params_x25519,
		   parse_algoid_pubkey_params_x448,
		   parse_algoid_pubkey_params_rsa,
		   parse_algoid_pubkey_params_gost_r3410_2012_256,
		   parse_algoid_pubkey_params_gost_r3410_2012_512,
		   parse_algoid_pubkey_params_gost_r3410_2001,
		   parse_algoid_pubkey_params_gost_r3410_94,
		   parse_algoid_pubkey_params_dsa,
		   parse_algoid_pubkey_params_ea_rsa,
		   parse_algoid_pubkey_params_none,
		   parse_algoid_pubkey_params_bign; @*/
	ret = talg->parse_algoid_pubkey_params(ctx, cert, off, param_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len)); */
	/*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve)); */
	/*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_ecPublicKey ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len)); */
	/*@ assert talg->parse_algoid_pubkey_params == parse_algoid_pubkey_params_ecPublicKey ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve)); */

	/*@ assert talg->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len)); */
	/*@ assert talg->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve)); */
	/*@ assert talg->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len)); */
	/*@ assert talg->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve)); */

	parsed = hdr_len + data_len;
	*alg = talg;
	/*@ assert (*alg)->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len)); */
	/*@ assert (*alg)->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve)); */
	/*@ assert (*alg)->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len)); */
	/*@ assert (*alg)->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve)); */
	*eaten = parsed;
	ctx->spki_alg = talg->pubkey_id;
	ctx->spki_alg_oid_start = saved_off;
	ctx->spki_alg_oid_len = parsed;

	ret = 0;

out:
	return ret;
}

static const u8 _dn_oid_cn[] =        { 0x06, 0x03, 0x55, 0x04, 0x03 };
static const u8 _dn_oid_surname[] =   { 0x06, 0x03, 0x55, 0x04, 0x04 };
static const u8 _dn_oid_serial[] =    { 0x06, 0x03, 0x55, 0x04, 0x05 };
static const u8 _dn_oid_country[] =   { 0x06, 0x03, 0x55, 0x04, 0x06 };
static const u8 _dn_oid_locality[] =  { 0x06, 0x03, 0x55, 0x04, 0x07 };
static const u8 _dn_oid_state[] =     { 0x06, 0x03, 0x55, 0x04, 0x08 };
static const u8 _dn_oid_org[] =       { 0x06, 0x03, 0x55, 0x04, 0x0a };
static const u8 _dn_oid_org_unit[] =  { 0x06, 0x03, 0x55, 0x04, 0x0b };
static const u8 _dn_oid_title[] =     { 0x06, 0x03, 0x55, 0x04, 0x0c };
static const u8 _dn_oid_name[] =      { 0x06, 0x03, 0x55, 0x04, 0x29 };
static const u8 _dn_oid_emailaddress[] = { 0x06, 0x09, 0x2a, 0x86, 0x48,
					   0x86, 0xf7, 0x0d, 0x01, 0x09,
					   0x01  };
static const u8 _dn_oid_given_name[] = { 0x06, 0x03, 0x55, 0x04, 0x2a };
static const u8 _dn_oid_initials[] =  { 0x06, 0x03, 0x55, 0x04, 0x2b };
static const u8 _dn_oid_gen_qual[] =  { 0x06, 0x03, 0x55, 0x04, 0x2c };
static const u8 _dn_oid_dn_qual[] =   { 0x06, 0x03, 0x55, 0x04, 0x2e };
static const u8 _dn_oid_pseudo[] =    { 0x06, 0x03, 0x55, 0x04, 0x41 };
static const u8 _dn_oid_dc[] =        { 0x06, 0x0a, 0x09, 0x92, 0x26,
					0x89, 0x93, 0xf2, 0x2c, 0x64,
					0x01, 0x19 };
static const u8 _dn_oid_ogrn[] =      { 0x06, 0x05, 0x2a, 0x85, 0x03,
					0x64, 0x01 };
static const u8 _dn_oid_snils[] =     { 0x06, 0x05, 0x2a, 0x85, 0x03,
					0x64, 0x03 };
static const u8 _dn_oid_ogrnip[] =    { 0x06, 0x05, 0x2a, 0x85, 0x03,
					0x64, 0x05 };
static const u8 _dn_oid_inn[] =       { 0x06, 0x08, 0x2a, 0x85, 0x03,
					0x03, 0x81, 0x03, 0x01, 0x01 };
static const u8 _dn_oid_street_address[] = { 0x06, 0x03, 0x55, 0x04, 0x09 };

/*
 * This function verify given buffer contains a valid UTF-8 string
 * -1 is returned on error, 0 on success.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_utf8_string(const u8 *buf, u32 len)
{
	int ret;
	u8 b0;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@
	  @ loop invariant \valid_read(buf + (0 .. (len - 1)));
	  @ loop assigns b0, len, buf, ret;
	  @ loop variant len;
	  @ */
	while (len) {
		b0 = buf[0];

		/*
		 * CP encoded on a single byte, coding from 1 to 7 bits,
		 * U+000 to U+07FF.
		 */

		if (b0 <= 0x7f) {                   /* 0x00 to 0x7f */
			len -= 1;
			buf += 1;
			continue;
		}

		/*
		 * CP encoded on 2 bytes, coding from 8 to 11 bits,
		 * U+0080 to U+07FF
		 */

		if ((b0 >= 0xc2) && (b0 <= 0xdf)) { /* 0xc2 to 0xdf */
			if (len < 2) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			/*@ assert \valid_read(buf + (0 .. 1)); */
			if ((buf[1] & 0xc0) != 0x80) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			len -= 2;
			buf += 2;
			continue;
		}

		/*
		 * CP encoded on 3 bytes, coding 12 to 16 bits,
		 * U+0800 to U+FFFF.
		 */

		if ((b0 >= 0xe0) && (b0 <= 0xef)) { /* 0xe0 to 0xef */
			if (len < 3) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			/*@ assert \valid_read(buf + (0 .. 2)); */
			if (((buf[1] & 0xc0) != 0x80) ||
			    ((buf[2] & 0xc0) != 0x80)) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			/*
			 * 1rst byte is 0xe0 => 2nd byte in [0xa0, 0xbf]
			 * 1rst byte is 0xed => 2nd byte in [0x80, 0x9f]
			 */
			if ((b0 == 0xe0) &&
			    ((buf[1] < 0xa0) || (buf[1] > 0xbf))) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			} else if ((b0 == 0xed) &&
				   ((buf[1] < 0x80) || (buf[1] > 0x9f))) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			len -= 3;
			buf += 3;
			continue;
		}

		/*
		 * CP encoded on 4 bytes, coding 17 to 21 bits,
		 * U+10000 to U+10FFFF.
		 */

		if ((b0 >= 0xf0) && (b0 <= 0xf4)) { /* 0xf0 to 0xf4 */
			if (len < 4) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			/*
			 * 1rst byte is 0xe0 => 2nd byte in [0xa0, 0xbf]
			 * 1rst byte is 0xed => 2nd byte in [0x80, 0x9f]
			 */
			/*@ assert \valid_read(buf + (0 .. 3)); */
			if ((b0 == 0xf0) &&
			    ((buf[1] < 0x90) || (buf[1] > 0xbf))) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			} else if ((b0 == 0xf4) &&
				   ((buf[1] < 0x80) || (buf[1] > 0x8f))) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			if (((buf[1] & 0xc0) != 0x80) ||
			    ((buf[2] & 0xc0) != 0x80) ||
			    ((buf[3] & 0xc0) != 0x80)) {
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			len -= 4;
			buf += 4;
			continue;
		}

		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * Verify given buffer contains only printable characters. -1 is
 * returned on error, 0 on success.
 *
 * RFC 5280 has: "The character string type PrintableString supports a
 * very basic Latin character set: the lowercase letters 'a' through 'z',
 * uppercase letters 'A' through 'Z', the digits '0' through '9',
 * eleven special characters ' = ( ) + , - . / : ? and space."
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_printable_string(const u8 *buf, u32 len)
{
	int ret;
	u32 rbytes;
	u8 c;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@
	  @ loop invariant 0 <= rbytes <= len;
	  @ loop assigns rbytes, c, ret;
	  @ loop variant (len - rbytes);
	  @ */
	for (rbytes = 0; rbytes < len; rbytes++) {
		c = buf[rbytes];

		if ((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9')) {
			continue;
		}

		switch (c) {
		case 39: /* ' */
		case '=':
		case '(':
		case ')':
		case '+':
		case ',':
		case '-':
		case '.':
		case '/':
		case ':':
		case '?':
		case ' ':
			continue;
		default:
			break;
		}

		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * Verify given buffer contains only numeric characters. -1 is
 * returned on error, 0 on success.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_numeric_string(const u8 *buf, u32 len)
{
	int ret;
	u32 rbytes;
	u8 c;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@
	  @ loop invariant 0 <= rbytes <= len;
	  @ loop assigns rbytes, c, ret;
	  @ loop variant (len - rbytes);
	  @ */
	for (rbytes = 0; rbytes < len; rbytes++) {
		c = buf[rbytes];

		if ((c < '0') || (c > '9')) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	ret = 0;

out:
	return ret;
}

/*
 * VisibleString == ISO646String == ASCII
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_visible_string(const u8 *buf, u32 len)
{
	int ret;
	u32 rbytes = 0;
	u8 c;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@
	  @ loop assigns rbytes, c, ret;
	  @ loop variant (len - rbytes);
	  @ */
	while (rbytes < len) {
		c = buf[rbytes];

		if ((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9')) {
			rbytes += 1;
			continue;
		}

		switch (c) {
		case 39: /* ' */
		case '=':
		case '(':
		case ')':
		case '+':
		case ',':
		case '-':
		case '.':
		case '/':
		case ':':
		case '?':
		case ' ':
		case '!':
		case '"':
		case '#':
		case '$':
		case '%':
		case '&':
		case '*':
		case ';':
		case '<':
		case '>':
		case '[':
		case '\\':
		case ']':
		case '^':
		case '_':
		case '`':
		case '{':
		case '|':
		case '}':
		case '~':
			rbytes += 1;
			continue;
		default:
			break;
		}

		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

#ifdef TEMPORARY_LAXIST_DIRECTORY_STRING
/*
 * Teletex string is not supposed to be supported and there is no good
 * defintiion of allowed charset. At the moment, we perform the check
 * using printable string charset
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_teletex_string(const u8 *buf, u32 len)
{
	return check_printable_string(buf, len);
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_universal_string(const u8 ATTRIBUTE_UNUSED *buf,
				  u32 ATTRIBUTE_UNUSED len)
{
	return -__LINE__;
}
#endif

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_bmp_string(const u8 ATTRIBUTE_UNUSED *buf,
			    u32 ATTRIBUTE_UNUSED len)
{
	/* Support is OPTIONAL */
	return -__LINE__;
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_ia5_string(const u8 *buf, u32 len)
{
	int ret;
	u32 i;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@
	  @ loop invariant \forall integer x ; 0 <= x < i ==>
		 ((buf[x] <= 0x7f));
	  @ loop assigns i;
	  @ loop variant (len - i);
	  @ */
	for (i = 0; i < len; i++) {
		if (buf[i] > 0x7f) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	ret = 0;

out:
	return ret;
}

/*
 * Most RDN values are encoded using the directory string type
 * defined below. This function performs the required check to
 * verify the given string is a valid DirectoryString. The
 * function returns 0 on success and -1 on error.
 *
 * This is an error if the length does not match that of the
 * string, if buffer is too short or too long for the encoded
 * string.
 *
 *  DirectoryString ::= CHOICE {
 *        teletexString           TeletexString (SIZE (1..MAX)),
 *        printableString         PrintableString (SIZE (1..MAX)),
 *        universalString         UniversalString (SIZE (1..MAX)),
 *        utf8String              UTF8String (SIZE (1..MAX)),
 *        bmpString               BMPString (SIZE (1..MAX)) }
 *
 *
 * 'len' is the size of given buffer, including string type
 * and string length. 'lb' and 'ub' are respectively lower and
 * upper bounds for the effective string.
 *
 * Note that RFC 5280 has the following: "upper bounds on string types,
 * such as TeletexString, are measured in characters.  Excepting
 * PrintableString or IA5String, a significantly greater number of
 * octets will be required to hold  such a value.  As a minimum, 16
 * octets, or twice the specified  upper bound, whichever is the larger,
 * should be allowed for TeletexString.  For UTF8String or UniversalString
 * at least four times the upper bound should be allowed.
 *
 */
#define STR_TYPE_UTF8_STRING      12
#define STR_TYPE_NUMERIC_STRING   18
#define STR_TYPE_PRINTABLE_STRING 19
#define STR_TYPE_TELETEX_STRING   20
#define STR_TYPE_IA5_STRING       22
#define STR_TYPE_VISIBLE_STRING   26
#define STR_TYPE_UNIVERSAL_STRING 28
#define STR_TYPE_BMP_STRING       30
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_directory_string(const u8 *buf, u32 len, u32 lb, u32 ub)
{
	int ret = -__LINE__;
	u8 str_type;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len < 2) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	str_type = buf[0];

	len -= 2;
	if (buf[1] != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 2;

	if ((len < lb) || (len > ub)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	switch (str_type) {
	case STR_TYPE_PRINTABLE_STRING:
		ret = check_printable_string(buf, len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	case STR_TYPE_UTF8_STRING:
		ret = check_utf8_string(buf, len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
#ifdef TEMPORARY_LAXIST_DIRECTORY_STRING
		/*
		 * Section 4.1.2.4 of RFC 5280 has "CAs conforming to this
		 * profile MUST use either the PrintableString or UTF8String
		 * encoding of DirectoryString, with two exceptions
		 */
	case STR_TYPE_TELETEX_STRING:
		ret = check_teletex_string(buf, len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	case STR_TYPE_UNIVERSAL_STRING:
		ret = check_universal_string(buf, len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	case STR_TYPE_BMP_STRING:
		ret = check_bmp_string(buf, len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	case STR_TYPE_IA5_STRING:
		ret = check_ia5_string(buf, len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	case STR_TYPE_NUMERIC_STRING:
		ret = check_numeric_string(buf, len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
#endif
	default:
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		break;
	}

	if (ret) {
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * Some RDN values are specifically encoded as PrintableString and the usual
 * directoryString. The function verifies that. It returns -1 on error, 0
 * on success.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_printable_string(const u8 *buf, u32 len, u32 lb, u32 ub)
{
	int ret = -__LINE__;
	u8 str_type;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len < 2) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	str_type = buf[0];
	if (str_type != STR_TYPE_PRINTABLE_STRING) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	len -= 2;
	if (buf[1] != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 2;

	if ((len < lb) || (len > ub)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = check_printable_string(buf, len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * Some RDN values are specifically encoded as NumericString. The function
 * verifies that. It returns -1 on error, 0 on success.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_numeric_string(const u8 *buf, u32 len, u32 lb, u32 ub)
{
	int ret = -__LINE__;
	u8 str_type;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len < 2) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	str_type = buf[0];
	if (str_type != STR_TYPE_NUMERIC_STRING) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	len -= 2;
	if (buf[1] != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 2;

	if ((len < lb) || (len > ub)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = check_numeric_string(buf, len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * As pointed by RFC 4519 and described by RFC 4517, IA5String
 * is defined in ABNF form as *(%x00-7F).
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ia5_string(const u8 *buf, u32 len, u32 lb, u32 ub)
{
	int ret = -__LINE__;
	u8 str_type;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len < 2) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	str_type = buf[0];
	if (str_type != STR_TYPE_IA5_STRING) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	len -= 2;
	if (buf[1] != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 2;

	if ((len < lb) || (len > ub)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = check_ia5_string(buf, len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

#ifdef TEMPORARY_LAXIST_EMAILADDRESS_WITH_UTF8_ENCODING
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures \result == 0 ==> ((len >= 2) && (lb <= len - 2 <= ub));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_utf8_string(const u8 *buf, u32 len, u32 lb, u32 ub)
{
	int ret = -__LINE__;
	u8 str_type;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len < 2) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	str_type = buf[0];
	if (str_type != STR_TYPE_IA5_STRING) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	len -= 2;
	if (buf[1] != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 2;

	if ((len < lb) || (len > ub)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = check_utf8_string(buf, len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}
#endif

/*
 *
 * -- Naming attributes of type X520CommonName:
 * --   X520CommonName ::= DirectoryName (SIZE (1..ub-common-name))
 * --
 * -- Expanded to avoid parameterized type:
 * X520CommonName ::= CHOICE {
 *       teletexString     TeletexString   (SIZE (1..ub-common-name)),
 *       printableString   PrintableString (SIZE (1..ub-common-name)),
 *       universalString   UniversalString (SIZE (1..ub-common-name)),
 *       utf8String        UTF8String      (SIZE (1..ub-common-name)),
 *       bmpString         BMPString       (SIZE (1..ub-common-name)) }
 */
#ifdef TEMPORARY_LAXIST_RDN_UPPER_BOUND
#define UB_COMMON_NAME 192
#else
#define UB_COMMON_NAME 64
#endif
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_cn(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_COMMON_NAME);
}

#define UB_NAME 32768
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_x520name(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_NAME);
}

#define UB_EMAILADDRESS 255
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_emailaddress(const u8 *buf, u32 len)
{
	int ret;

	/* RFC 5280 has:
	 *
	 * "Legacy implementations exist where an electronic mail address is
	 * embedded in the subject distinguished name as an emailAddress
	 * attribute [RFC2985].  The attribute value for emailAddress is of
	 * type IA5String to permit inclusion of the character '@', which is
	 * not part of the PrintableString character set.  emailAddress
	 * attribute values are not case-sensitive (e.g.,
	 * "subscriber@example.com" is the same as "SUBSCRIBER@EXAMPLE.COM").
	 *
	 * Conforming implementations generating new certificates with
	 * electronic mail addresses MUST use the rfc822Name in the subject
	 * alternative name extension (Section 4.2.1.6) to describe such
	 * identities.  Simultaneous inclusion of the emailAddress attribute
	 * in the subject distinguished name to support legacy implementations
	 * is deprecated but permitted."
	 */
	ret = parse_ia5_string(buf, len, 1, UB_EMAILADDRESS);

	/*
	 * As a side note, tests performed on our set indicates some
	 * implementations currently use UTF8 encoding for emailAddress.
	 * Hence the quirks below to support the (invalid) certificates
	 * generated by those implementations.
	 */
#ifdef TEMPORARY_LAXIST_EMAILADDRESS_WITH_UTF8_ENCODING
	if (ret) {
		ret = parse_utf8_string(buf, len, 1, UB_EMAILADDRESS);
	}
#endif

	return ret;
}

#define UB_SERIAL_NUMBER 64
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_serial(const u8 *buf, u32 len)
{
	int ret;

	ret = parse_printable_string(buf, len, 1, UB_SERIAL_NUMBER);
	if (ret) {
#ifdef TEMPORARY_LAXIST_SERIAL_RDN_AS_IA5STRING
		ret = parse_ia5_string(buf, len, 1, UB_SERIAL_NUMBER);
#endif
	}

	return ret;
}

#define UB_COUNTRY 2
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_country(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, UB_COUNTRY, UB_COUNTRY);
}

#define UB_LOCALITY_NAME 128
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_locality(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_LOCALITY_NAME);
}

#define UB_STATE_NAME 128
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_state(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_STATE_NAME);
}

#ifdef TEMPORARY_LAXIST_RDN_UPPER_BOUND
#define UB_ORGANIZATION_NAME 64
#else
#define UB_ORGANIZATION_NAME 128
#endif
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_org(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_ORGANIZATION_NAME);
}

#ifdef TEMPORARY_LAXIST_RDN_UPPER_BOUND
#define UB_ORGANIZATION_UNIT_NAME 128
#else
#define UB_ORGANIZATION_UNIT_NAME 64
#endif
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_org_unit(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_ORGANIZATION_UNIT_NAME);
}

#define UB_TITLE_NAME 64
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_title(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_TITLE_NAME);
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_dn_qual(const u8 *buf, u32 len)
{
	/*
	 * There is no specific limit on that one, so giving the maximum
	 * buffer size we support will do the job.
	 */
	return parse_printable_string(buf, len, 1, ASN1_MAX_BUFFER_SIZE);
}

/*@
  @ assigns \nothing;
  @*/
static inline int _is_digit(u8 c)
{
	return ((c >= '0') && (c <= '9'));
}

/*@
  @ assigns \nothing;
  @*/
static inline int _is_alpha(u8 c)
{
	return (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')));
}

/*
 * As point in RFC 5280 and defined in section 2.4 of RFC 4519,
 * 'dc' (domainComponent) is a string attribute type holding a
 * DNS label. It is encoded as an IA5String. The ABNF for the
 * label is the following:
 *
 * label = (ALPHA / DIGIT) [*61(ALPHA / DIGIT / HYPHEN) (ALPHA / DIGIT)]
 * ALPHA   = %x41-5A / %x61-7A     ; "A"-"Z" / "a"-"z"
 * DIGIT   = %x30-39               ; "0"-"9"
 * HYPHEN  = %x2D                  ; hyphen ("-")
 *
 * To simplify things, we first verify this is a valid IA5string and then
 * verify the additional restrictions given above for the label.
 *
 * Note that RFC 2181 (Clarifications on DNS) has the following: "The DNS
 * itself places only one restriction on the particular labels that can
 * be used to identify resource records.  That one restriction relates
 * to the length of the label and the full name...". In the case of dc
 * attributes, limitations are imposed by the use of IA5String for
 * encoding and by the ABNF above.
 */
#define UB_DC 63
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_dc(const u8 *buf, u32 len)
{
	int ret;
	u32 i;
	u8 c;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* We expect an IA5String */
	ret = parse_ia5_string(buf, len, 1, UB_DC);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += 2;
	len -= 2;

	/* Restriction on first byte */
	c = buf[0];
	ret = _is_alpha(c) || _is_digit(c);
	if (!ret) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += 1;
	len -= 1;

	if (!len) { /* over ? */
		ret = 0;
		goto out;
	}

	/* Restriction on last byte if any */
	c = buf[len - 1];
	ret = _is_alpha(c) || _is_digit(c);
	if (!ret) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += 1;
	len -= 1;

	/* Restriction on middle bytes */
	/*@
	  @ loop invariant 0 <= i <= len;
	  @ loop assigns c, ret, i;
	  @ loop variant (len - i);
	  @ */
	for (i = 0; i < len; i++) {
		c = buf[i];
		ret = _is_digit(c) || _is_alpha(c) || (c == '-');
		if (!ret) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	ret = 0;

out:
	return ret;
}

#define UB_PSEUDONYM 128
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_pseudo(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_PSEUDONYM);
}


/* From section 5.1 of draft-deremin-rfc4491-bis-01 */

/* OGRN is the main state registration number of juridical entities */
#define UB_OGRN 13
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_ogrn(const u8 *buf, u32 len)
{
	return parse_numeric_string(buf, len, 1, UB_OGRN);
}

/* SNILS is the individual insurance account number */
#define UB_SNILS 11
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_snils(const u8 *buf, u32 len)
{
	return parse_numeric_string(buf, len, 1, UB_SNILS);
}

/*
 * OGRNIP is the main state registration number of individual
 * enterpreneurs
 */
#define UB_OGRNIP 15
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_ogrnip(const u8 *buf, u32 len)
{
	return parse_numeric_string(buf, len, 1, UB_OGRNIP);
}

/* INN is the individual taxpayer number (ITN). */
#define UB_INN 12
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_inn(const u8 *buf, u32 len)
{
	return parse_numeric_string(buf, len, 1, UB_INN);
}

/* street address. */
#define UB_STREET_ADDRESS 64 /* XXX FIXME Don't know what the limit is */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_street_address(const u8 *buf, u32 len)
{
	return parse_directory_string(buf, len, 1, UB_STREET_ADDRESS);
}

typedef struct {
	const u8 *oid;
	u8 oid_len;
	int (*parse_rdn_val)(const u8 *buf, u32 len);
} _name_oid;

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @
  @ assigns \nothing;
  @*/
static int parse_rdn_val_bad_oid(const u8 *buf, u32 len)
{
	(void) buf;
	(void) len;
	return 0;
}

static const _name_oid generic_unsupported_rdn_oid = {
	.oid = NULL,
	.oid_len = 0,
	.parse_rdn_val = parse_rdn_val_bad_oid
};

static const _name_oid known_dn_oids[] = {
	{ .oid = _dn_oid_cn,
	  .oid_len = sizeof(_dn_oid_cn),
	  .parse_rdn_val = parse_rdn_val_cn
	},
	{ .oid = _dn_oid_surname,
	  .oid_len = sizeof(_dn_oid_surname),
	  .parse_rdn_val = parse_rdn_val_x520name
	},
	{ .oid = _dn_oid_serial,
	  .oid_len = sizeof(_dn_oid_serial),
	  .parse_rdn_val = parse_rdn_val_serial
	},
	{ .oid = _dn_oid_country,
	  .oid_len = sizeof(_dn_oid_country),
	  .parse_rdn_val = parse_rdn_val_country
	},
	{ .oid = _dn_oid_locality,
	  .oid_len = sizeof(_dn_oid_locality),
	  .parse_rdn_val = parse_rdn_val_locality
	},
	{ .oid = _dn_oid_state,
	  .oid_len = sizeof(_dn_oid_state),
	  .parse_rdn_val = parse_rdn_val_state
	},
	{ .oid = _dn_oid_org,
	  .oid_len = sizeof(_dn_oid_org),
	  .parse_rdn_val = parse_rdn_val_org
	},
	{ .oid = _dn_oid_org_unit,
	  .oid_len = sizeof(_dn_oid_org_unit),
	  .parse_rdn_val = parse_rdn_val_org_unit
	},
	{ .oid = _dn_oid_title,
	  .oid_len = sizeof(_dn_oid_title),
	  .parse_rdn_val = parse_rdn_val_title
	},
	{ .oid = _dn_oid_name,
	  .oid_len = sizeof(_dn_oid_name),
	  .parse_rdn_val = parse_rdn_val_x520name
	},
	{ .oid = _dn_oid_emailaddress,
	  .oid_len = sizeof(_dn_oid_emailaddress),
	  .parse_rdn_val = parse_rdn_val_emailaddress
	},
	{ .oid = _dn_oid_given_name,
	  .oid_len = sizeof(_dn_oid_given_name),
	  .parse_rdn_val = parse_rdn_val_x520name
	},
	{ .oid = _dn_oid_initials,
	  .oid_len = sizeof(_dn_oid_initials),
	  .parse_rdn_val = parse_rdn_val_x520name
	},
	{ .oid = _dn_oid_gen_qual,
	  .oid_len = sizeof(_dn_oid_gen_qual),
	  .parse_rdn_val = parse_rdn_val_x520name
	},
	{ .oid = _dn_oid_dn_qual,
	  .oid_len = sizeof(_dn_oid_dn_qual),
	  .parse_rdn_val = parse_rdn_val_dn_qual
	},
	{ .oid = _dn_oid_pseudo,
	  .oid_len = sizeof(_dn_oid_pseudo),
	  .parse_rdn_val = parse_rdn_val_pseudo
	},
	{ .oid = _dn_oid_dc,
	  .oid_len = sizeof(_dn_oid_dc),
	  .parse_rdn_val = parse_rdn_val_dc
	},
	{ .oid = _dn_oid_ogrn,
	  .oid_len = sizeof(_dn_oid_ogrn),
	  .parse_rdn_val = parse_rdn_val_ogrn
	},
	{ .oid = _dn_oid_snils,
	  .oid_len = sizeof(_dn_oid_snils),
	  .parse_rdn_val = parse_rdn_val_snils
	},
	{ .oid = _dn_oid_ogrnip,
	  .oid_len = sizeof(_dn_oid_ogrnip),
	  .parse_rdn_val = parse_rdn_val_ogrnip
	},
	{ .oid = _dn_oid_inn,
	  .oid_len = sizeof(_dn_oid_inn),
	  .parse_rdn_val = parse_rdn_val_inn
	},
	{ .oid = _dn_oid_street_address,
	  .oid_len = sizeof(_dn_oid_street_address),
	  .parse_rdn_val = parse_rdn_val_street_address
	},
};

#define NUM_KNOWN_DN_OIDS (sizeof(known_dn_oids) / sizeof(known_dn_oids[0]))

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_DN_OIDS && \result == &known_dn_oids[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static const _name_oid * find_dn_by_oid(const u8 *buf, u32 len)
{
	const _name_oid *found = NULL;
	const _name_oid *cur = NULL;
	u8 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@ loop unroll NUM_KNOWN_DN_OIDS ;
	  @ loop invariant 0 <= k <= NUM_KNOWN_DN_OIDS;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_DN_OIDS - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_DN_OIDS; k++) {
		int ret;

		cur = &known_dn_oids[k];

		/*@ assert cur == &known_dn_oids[k];*/
		if (cur->oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->oid, buf, cur->oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}

/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY -- DEFINED BY AttributeType
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(buf+(..), eaten);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_AttributeTypeAndValue(const u8 *buf, u32 len, u32 *eaten)
{
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 oid_len = 0;
	u32 parsed;
	const _name_oid *cur = NULL;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* ... of SEQUENCEs ... */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	parsed = hdr_len + data_len;
	/*@ assert parsed <= len ; */

	buf += hdr_len;
	len -= hdr_len;

	/* ... Containing an OID ... */
	ret = parse_OID(buf, data_len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	cur = find_dn_by_oid(buf, oid_len);
	if (cur == NULL) {
#ifndef TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_RDN_OIDS
		/*
		 * OID not found => over. The trick below is a nop
		 * to let generic_unsupported_rdn_oid and
		 * parse_rdn_val_bad_oid() it contains be available
		 * and defined for Frama-C in all cases for the assert
		 * and calls just below.
		 */
		(void)generic_unsupported_rdn_oid;
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
#else
		cur = &generic_unsupported_rdn_oid;
#endif
	}

	data_len -= oid_len;
	buf += oid_len;

	/*
	 * Let's now check the value associated w/ and
	 * following the OID has a valid format.
	 */
	/*@ assert cur->parse_rdn_val \in {
		  parse_rdn_val_cn, parse_rdn_val_x520name,
		  parse_rdn_val_serial, parse_rdn_val_country,
		  parse_rdn_val_locality, parse_rdn_val_state,
		  parse_rdn_val_org, parse_rdn_val_org_unit,
		  parse_rdn_val_title,  parse_rdn_val_dn_qual,
		  parse_rdn_val_pseudo, parse_rdn_val_dc,
		  parse_rdn_val_ogrn, parse_rdn_val_snils,
		  parse_rdn_val_ogrnip, parse_rdn_val_inn,
		  parse_rdn_val_street_address,
		  parse_rdn_val_emailaddress,
		  parse_rdn_val_bad_oid };
	  @*/
	/*@ calls parse_rdn_val_cn, parse_rdn_val_x520name,
		  parse_rdn_val_serial, parse_rdn_val_country,
		  parse_rdn_val_locality, parse_rdn_val_state,
		  parse_rdn_val_org, parse_rdn_val_org_unit,
		  parse_rdn_val_title, parse_rdn_val_dn_qual,
		  parse_rdn_val_pseudo, parse_rdn_val_dc,
		  parse_rdn_val_ogrn, parse_rdn_val_snils,
		  parse_rdn_val_ogrnip, parse_rdn_val_inn,
		  parse_rdn_val_street_address,
		  parse_rdn_val_emailaddress,
		  parse_rdn_val_bad_oid;
	  @*/
	ret = cur->parse_rdn_val(buf, data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = parsed;
	/*@ assert *eaten <= \at(len,Pre) ; */

	ret = 0;

out:
	return ret;
}

/*
 *  RelativeDistinguishedName ::=
 *    SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten,buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_RelativeDistinguishedName(const u8 *buf, u32 len, u32 *eaten)
{
	u32 hdr_len = 0;
	u32 data_len = 0;
	u32 rdn_remain, saved_rdn_len;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Each RDN is a SET ... */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SET,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	saved_rdn_len = hdr_len + data_len;
	buf += hdr_len;
	rdn_remain = data_len;

	/*@
	  @ loop assigns ret, buf, rdn_remain;
	  @ loop invariant \valid_read(buf + (0 .. (rdn_remain - 1)));
	  @ loop variant rdn_remain;
	  @ */
	while (rdn_remain) {
		u32 parsed = 0;

		ret = parse_AttributeTypeAndValue(buf, rdn_remain, &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * FIXME! we should check the amount of AttributeTypeAndValue
		 * elements is between 1 and MAX
		 */

		rdn_remain -= parsed;
		buf += parsed;
	}

	*eaten = saved_rdn_len;

	ret = 0;

out:
	return ret;
}


/*
 * Used for Issuer and subject
 *
 *  Name ::= CHOICE { -- only one possibility for now --
 *    rdnSequence  RDNSequence }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::=
 *    SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY -- DEFINED BY AttributeType
 *
 * Here is what section 4.1.2.4 of RFC 5280 has:
 *
 * As noted above, distinguished names are composed of attributes.  This
 * specification does not restrict the set of attribute types that may
 * appear in names.  However, conforming implementations MUST be
 * prepared to receive certificates with issuer names containing the set
 * of attribute types defined below.  This specification RECOMMENDS
 * support for additional attribute types.
 *
 * Standard sets of attributes have been defined in the X.500 series of
 * specifications [X.520].  Implementations of this specification MUST
 * be prepared to receive the following standard attribute types in
 * issuer and subject (Section 4.1.2.6) names:
 *
 *    * country,
 *    * organization,
 *    * organizational unit,
 *    * distinguished name qualifier,
 *    * state or province name,
 *    * common name (e.g., "Susan Housley"), and
 *    * serial number.
 *
 * In addition, implementations of this specification SHOULD be prepared
 * to receive the following standard attribute types in issuer and
 * subject names:
 *
 *    * locality,
 *    * title,
 *    * surname,
 *    * given name,
 *    * initials,
 *    * pseudonym, and
 *    * generation qualifier (e.g., "Jr.", "3rd", or "IV").
 *
 * The syntax and associated object identifiers (OIDs) for these
 * attribute types are provided in the ASN.1 modules in Appendix A.
 *
 * In addition, implementations of this specification MUST be prepared
 * to receive the domainComponent attribute, as defined in [RFC4519].
 * The Domain Name System (DNS) provides a hierarchical resource
 * labeling system.  This attribute provides a convenient mechanism for
 * organizations that wish to use DNs that parallel their DNS names.
 * This is not a replacement for the dNSName component of the
 * alternative name extensions.  Implementations are not required to
 * convert such names into DNS names.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, empty, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (\result == 0) ==> ((*empty == 0) || (*empty == 1));
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten, *empty;
  @*/
static int parse_x509_Name(const u8 *buf, u32 len, u32 *eaten, int *empty)
{
	u32 name_hdr_len = 0;
	u32 name_data_len = 0;
	u32 remain = 0;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &name_hdr_len, &name_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += name_hdr_len;
	remain = name_data_len;

	/*@
	  @ loop assigns ret, buf, remain;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop variant remain;
	  @ */
	while (remain) {
		u32 parsed = 0;

		ret = parse_RelativeDistinguishedName(buf, remain, &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += parsed;
		remain -= parsed;
	}

	*eaten = name_hdr_len + name_data_len;
	*empty = !name_data_len;
	/*@ assert (*empty == 0) ||  (*empty == 1); */

	ret = 0;

out:
	return ret;
}

/*@
  @ requires 0x30 <= d <= 0x39;
  @ requires 0x30 <= u <= 0x39;
  @
  @ ensures 0 <= \result <= 99;
  @
  @ assigns \nothing;
  @*/
u8 compute_decimal(u8 d, u8 u)
{
	return (d - 0x30) * 10 + (u - 0x30);
}

/* Validate UTCTime (including the constraints from RFC 5280) */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(eaten);
  @ requires \valid(year);
  @ requires \valid(month);
  @ requires \valid(day);
  @ requires \valid(hour);
  @ requires \valid(min);
  @ requires \valid(sec);
  @ requires \separated(eaten, year, month, day, hour, min, sec, buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten == 15);
  @ ensures (len < 15) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten, *year, *month, *day, *hour, *min, *sec;
  @*/
static int parse_UTCTime(const u8 *buf, u32 len, u32 *eaten,
			 u16 *year, u8 *month, u8 *day,
			 u8 *hour, u8 *min, u8 *sec)
{
	u16 yyyy;
	u8 mo, dd, hh, mm, ss;
	const u8 c_zero = '0';
	u8 time_type;
	u8 time_len;
	int ret = -__LINE__;
	u8 i, tmp;

	if (buf == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * As described in section 4.1.2.5.1 of RFC 5280, we do
	 * expect the following encoding: YYMMDDHHMMSSZ, i.e.
	 * a length of at least 15 bytes for the buffer, i.e.
	 * an advertised length of 13 bytes for the string
	 * it contains.
	 */
	if (len < 15) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	time_type = buf[0];
	if (time_type != ASN1_TYPE_UTCTime) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	time_len = buf[1];
	if (time_len != 13) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 2;

	/*
	 * Check all first 12 characters are decimal digits and
	 * last one is character 'Z'
	 */
	/*@
	  @ loop invariant \valid_read(buf + i);
	  @ loop invariant \forall integer x ; 0 <= x < i ==>
		 0x30 <= buf[x] <= 0x39;
	  @ loop assigns i;
	  @ loop variant (12 - i);
	  @ */
	for (i = 0; i < 12; i++) {
		if (c_zero > buf[i]) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		if ((buf[i] - c_zero) > 9) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		/*@ assert 0 <= buf[i] - c_zero <= 9; */
	}
	if (buf[12] != 'Z') {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert c_zero == 0x30; */
	/*@ assert \forall integer x ; 0 <= x < 12 ==> 0x30 <= buf[x] <= 0x39; */
	yyyy = compute_decimal(buf[0], buf[1]);
	if (yyyy >= 50) {
		yyyy += 1900;
	} else {
		yyyy += 2000;
	}

	mo = compute_decimal(buf[ 2], buf[ 3]);
	dd = compute_decimal(buf[ 4], buf[ 5]);
	hh = compute_decimal(buf[ 6], buf[ 7]);
	mm = compute_decimal(buf[ 8], buf[ 9]);
	ss = compute_decimal(buf[10], buf[11]);

	/*
	 * Check values are valid (n.b.: no specific check required on
	 * the year, because UTC Time is guaranteed to be less than
	 * )
	 */
	tmp = 0;
	tmp |= mo > 12;  /* month */
	tmp |= dd > 31;  /* day   */
	tmp |= hh > 23;  /* hour  */
	tmp |= mm > 59;  /* min   */
	tmp |= ss > 59;  /* sec   */
	if (tmp) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Export what we extracted */
	*year  = yyyy;
	*month = mo;
	*day   = dd;
	*hour  = hh;
	*min   = mm;
	*sec   = ss;

	ret = 0;

out:
	if (!ret) {
		*eaten = 15;
	}

	return ret;
}

/*@
  @ requires 0x30 <= d1 <= 0x39;
  @ requires 0x30 <= d2 <= 0x39;
  @ requires 0x30 <= d3 <= 0x39;
  @ requires 0x30 <= d4 <= 0x39;
  @
  @ ensures 0 <= \result <= 9999;
  @
  @ assigns \nothing;
  @*/
u16 compute_year(u8 d1, u8 d2, u8 d3, u8 d4)
{
	return ((u16)d1 - (u16)0x30) * 1000 +
	       ((u16)d2 - (u16)0x30) * 100 +
	       ((u16)d3 - (u16)0x30) * 10 +
	       ((u16)d4 - (u16)0x30);
}

/*
 * Validate generalizedTime (including the constraints from RFC 5280). Note that
 * the code is very similar to the one above developed for UTCTime. It
 * could be possible to merge the functions into a unique helper
 * but this would impact readibility.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(year);
  @ requires \valid(month);
  @ requires \valid(day);
  @ requires \valid(hour);
  @ requires \valid(min);
  @ requires \valid(sec);
  @ requires \separated(eaten, year, month, day, hour, min, sec, buf + (0 .. (len - 1)));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten == 17);
  @ ensures (len < 17) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten, *year, *month, *day, *hour, *min, *sec;
  @*/
static int parse_generalizedTime(const u8 *buf, u32 len, u32 *eaten,
				 u16 *year, u8 *month, u8 *day,
				 u8 *hour, u8 *min, u8 *sec)
{
	u16 yyyy;
	u8 mo, dd, hh, mm, ss;
	const u8 c_zero = '0';
	u8 time_type;
	u8 time_len;
	int ret = -__LINE__;
	u8 i, tmp;

	if (buf == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * As described in section 4.1.2.5.2 of RFC 5280, we do
	 * expect the following encoding: YYYYMMDDHHMMSSZ, i.e.
	 * a length of at least 17 bytes for the buffer, i.e.
	 * an advertised length of 15 bytes for the string
	 * it contains.
	 */
	if (len < 17) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	time_type = buf[0];
	if (time_type != ASN1_TYPE_GeneralizedTime) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	time_len = buf[1];
	if (time_len != 15) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 2;

	/*
	 * Check all first 14 characters are decimal digits and
	 * last one is character 'Z'
	 */
	/*@
	  @ loop invariant \valid_read(buf + i);
	  @ loop invariant \forall integer x ; 0 <= x < i ==>
		 0x30 <= buf[x] <= 0x39;
	  @ loop assigns i;
	  @ loop variant (14 - i);
	  @ */
	for (i = 0; i < 14; i++) {
		if (c_zero > buf[i]) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		if ((buf[i] - c_zero) > 9) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}
	if (buf[14] != 'Z') {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert c_zero == 0x30; */
	/*@ assert \forall integer x ; 0 <= x < 12 ==> 0x30 <= buf[x] <= 0x39; */
	yyyy = compute_year(buf[0], buf[1], buf[2], buf[3]);
	mo = compute_decimal(buf[ 4], buf[ 5]);
	dd = compute_decimal(buf[ 6], buf[ 7]);
	hh = compute_decimal(buf[ 8], buf[ 9]);
	mm = compute_decimal(buf[10], buf[11]);
	ss = compute_decimal(buf[12], buf[13]);

	/*
	 * Check values are valid (n.b.: RFC 5280 requires the use of
	 * UTCTime for dates through the year 2049. Dates in 2050 or
	 * later MUST be encoded as GeneralizedTime.
	 */
	tmp = 0;
	tmp |= yyyy <= 2049; /* year  */
	tmp |= mo > 12;      /* month */
	tmp |= dd > 31;      /* day   */
	tmp |= hh > 23;      /* hour  */
	tmp |= mm > 59;      /* min   */
	tmp |= ss > 59;      /* sec   */
	if (tmp) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Export what we extracted */
	*year  = yyyy;
	*month = mo;
	*day   = dd;
	*hour  = hh;
	*min   = mm;
	*sec   = ss;

	ret = 0;

out:
	if (!ret) {
		*eaten = 17;
	}

	return ret;
}

/*
 * Time ::= CHOICE {
 *    utcTime        UTCTime,
 *    generalTime    GeneralizedTime }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(eaten);
  @ requires \valid(year);
  @ requires \valid(month);
  @ requires \valid(day);
  @ requires \valid(hour);
  @ requires \valid(min);
  @ requires \valid(sec);
  @ requires \separated(t_type,eaten,year,month,day,hour,min,sec,buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *t_type, *eaten, *year, *month, *day, *hour, *min, *sec;
  @*/
static int parse_Time(const u8 *buf, u32 len, u8 *t_type, u32 *eaten,
		      u16 *year, u8 *month, u8 *day,
		      u8 *hour, u8 *min, u8 *sec)
{
	u8 time_type;
	int ret = -__LINE__;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len < 2) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	time_type = buf[0];

	switch (time_type) {
	case ASN1_TYPE_UTCTime:
		ret = parse_UTCTime(buf, len, eaten, year, month,
				    day, hour, min, sec);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	case ASN1_TYPE_GeneralizedTime:
		ret = parse_generalizedTime(buf, len, eaten, year, month,
					    day, hour, min, sec);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
		}
		break;
	default:
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		break;
	}

	*t_type = time_type;

out:
	if (ret) {
		*eaten = 0;
	}
	return ret;
}

/*
 * RFC 5280 has "CAs conforming to this profile MUST always encode certificate
 * validity dates through the year 2049 as UTCTime; certificate validity dates
 * in 2050 or later MUST be encoded as GeneralizedTime."
 *
 * This function performs that simple check. It returns 0 on success, a non
 * zero value on error.
 */
/*@ ensures \result < 0 || \result == 0;
  @
  @ assigns \nothing;
  @*/
static int _verify_correct_time_use(u8 time_type, u16 yyyy)
{
	int ret;

	switch (time_type) {
	case ASN1_TYPE_UTCTime:
		ret = (yyyy <= 2049) ? 0 : -__LINE__;
		break;
	case ASN1_TYPE_GeneralizedTime:
		ret = (yyyy >= 2050) ? 0 : -__LINE__;
		break;
	default:
		ret = -1;
		break;
	}

	return ret;

}

/*
 * Verify Validity by checking it is indeed a sequence of two
 * valid UTCTime elements. Note that the function only perform
 * syntaxic checks on each element individually and does not
 * compare the two values together (e.g. to verify notBefore
 * is indeed before notAfter, etc).
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns *eaten, ctx->not_before, ctx->not_after;
  @*/
static int parse_x509_Validity(cert_parsing_ctx *ctx,
			       const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	const u8 *buf = cert + off;
	int ret;
	u32 hdr_len = 0;
	u32 remain = 0;
	u32 data_len = 0;
	u32 nb_len = 0, na_len = 0;
	u16 na_year = 0, nb_year = 0;
	u8 na_month = 0, na_day = 0, na_hour = 0, na_min = 0, na_sec = 0;
	u8 nb_month = 0, nb_day = 0, nb_hour = 0, nb_min = 0, nb_sec = 0;
	u8 t_type = 0;
	u64 not_after, not_before;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	/* Parse notBefore */
	ret = parse_Time(buf, remain, &t_type, &nb_len, &nb_year, &nb_month,
			 &nb_day, &nb_hour, &nb_min, &nb_sec);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check valid time type was used for year value */
	ret = _verify_correct_time_use(t_type, nb_year);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain -= nb_len;
	buf += nb_len;

	/* Parse notAfter */
	ret = parse_Time(buf, remain, &t_type, &na_len, &na_year, &na_month,
			 &na_day, &na_hour, &na_min, &na_sec);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check valid time type was used for year value */
	ret = _verify_correct_time_use(t_type, na_year);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain -= na_len;
	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * To export time to context we do not bother converting to unix
	 * but encode all the components on a u64 in the following way.
	 * this makes resulting not_after and not_before values comparable.
	 */
	not_after   = (((u64)na_year) << 40) + (((u64)na_month) << 32);
	not_after  +=  (((u64)na_day) << 24) +  (((u64)na_hour) << 16);
	not_after  +=  (((u64)na_min) <<  8) +  (((u64)na_sec));

	not_before  = (((u64)nb_year) << 40) + (((u64)nb_month) << 32);
	not_before +=  (((u64)nb_day) << 24) +  (((u64)nb_hour) << 16);
	not_before +=  (((u64)nb_min) <<  8) +  (((u64)nb_sec));

	if (not_before >= not_after) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->not_before = not_before;
	ctx->not_after = not_after;
	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/* SubjectPublicKeyInfo,
 *
 *    SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *         algorithm            AlgorithmIdentifier,
 *         subjectPublicKey     BIT STRING  }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_subjectPublicKeyInfo(cert_parsing_ctx *ctx,
					   const u8 *cert, u32 off, u32 len,
					   u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0, parsed = 0, remain = 0;
	u32 saved_off = off;
	const u8 *buf = cert + off;
	const _pubkey_alg *alg = NULL;
	int ret;

	if ((ctx == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;
	off += hdr_len;

	ret = parse_x509_pubkey_AlgorithmIdentifier(ctx, cert, off, remain,
						    &alg, &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert alg->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve_order_bit_len)); */
	/*@ assert alg->parse_pubkey == parse_pubkey_bign ==> \initialized(&(ctx->spki_alg_params.bign.curve)); */
	/*@ assert alg->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve_order_bit_len)); */
	/*@ assert alg->parse_pubkey == parse_pubkey_ec ==> \initialized(&(ctx->spki_alg_params.ecpubkey.curve)); */

	buf += parsed;
	remain -= parsed;
	off += parsed;

	/*
	 * Let's now check if subjectPublicKey is ok based on the
	 * algorithm and parameters we found.
	 */
	if (!alg->parse_pubkey) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert alg->parse_pubkey \in {
		  parse_pubkey_ed448,
		  parse_pubkey_x448,
		  parse_pubkey_ed25519,
		  parse_pubkey_x25519,
		  parse_pubkey_ec,
		  parse_pubkey_rsa,
		  parse_pubkey_gostr3410_94,
		  parse_pubkey_gostr3410_2001,
		  parse_pubkey_gostr3410_2012_256,
		  parse_pubkey_gostr3410_2012_512,
		  parse_pubkey_dsa,
		  parse_pubkey_bign } ; @*/
	/*@ calls parse_pubkey_ed448,
		  parse_pubkey_x448,
		  parse_pubkey_ed25519,
		  parse_pubkey_x25519,
		  parse_pubkey_ec,
		  parse_pubkey_rsa,
		  parse_pubkey_gostr3410_94,
		  parse_pubkey_gostr3410_2001,
		  parse_pubkey_gostr3410_2012_256,
		  parse_pubkey_gostr3410_2012_512,
		  parse_pubkey_dsa,
		  parse_pubkey_bign ; @*/
	ret = alg->parse_pubkey(ctx, cert, off, remain);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->spki_pub_key_start = off;
	ctx->spki_pub_key_len = remain;
	ctx->spki_start = saved_off;
	ctx->spki_len = hdr_len + data_len;
	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}


/*
 * Extensions -- optional
 */


#if 0
/* WIP! */

/*
 * RFC 5280 has "When the subjectAltName extension contains a domain name
 * system label, the domain name MUST be stored in the dNSName (an
 * IA5String). The name MUST be in the "preferred name syntax", as
 * specified by Section 3.5 of [RFC1034] and as modified by Section 2.1
 * of [RFC1123]. In addition, while the string " " is a legal domain name,
 * subjectAltName extensions with a dNSName of " " MUST NOT be used."
 *                                                              |
 * This function implements that checks, namely:                |
 *                                                              |
 * From 3.5 of RFC 1034:                                        |
 *                                                              |
 *    <domain> ::= <subdomain> | " "          " " not allowed --+
 *
 *    <subdomain> ::= <label> | <subdomain> "." <label>
 *
 *    <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]
 *
 *    <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
 *
 *    <let-dig-hyp> ::= <let-dig> | "-"
 *
 *    <let-dig> ::= <letter> | <digit>
 *
 *    <letter> ::= any one of the 52 alphabetic characters A through Z in
 *    upper case and a through z in lower case
 *
 *    <digit> ::= any one of the ten digits 0 through 9
 *
 *    Note that while upper and lower case letters are allowed in domain
 *    names, no significance is attached to the case.  That is, two names with
 *    the same spelling but different case are to be treated as if identical.
 *
 *    The labels must follow the rules for ARPANET host names.  They must
 *    start with a letter, end with a letter or digit, and have as interior
 *    characters only letters, digits, and hyphen.  There are also some
 *    restrictions on the length.  Labels must be 63 characters or less.
 *
 * From 2.1 of RFC 1123:
 *
 *    The syntax of a legal Internet host name was specified in RFC-952
 *    [DNS:4].  One aspect of host name syntax is hereby changed: the
 *    restriction on the first character is relaxed to allow either a
 *    letter or a digit.  Host software MUST support this more liberal
 *    syntax.
 *
 *    Host software MUST handle host names of up to 63 characters and
 *    SHOULD handle host names of up to 255 characters.
 *
 *    Whenever a user inputs the identity of an Internet host, it SHOULD
 *    be possible to enter either (1) a host domain name or (2) an IP
 *    address in dotted-decimal ("#.#.#.#") form.  The host SHOULD check
 *    the string syntactically for a dotted-decimal number before
 *    looking it up in the Domain Name System.
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int check_prefered_name_syntax(const u8 *buf, u32 len)
{

	/* FIXME! */

	ret = 0;

out:
	return ret;
}
#endif

/*
 * Parse GeneralName (used in SAN and AIA extensions)
 *
 *  GeneralName ::= CHOICE {
 *       otherName                 [0]  AnotherName,
 *       rfc822Name                [1]  IA5String,
 *       dNSName                   [2]  IA5String,
 *       x400Address               [3]  ORAddress,
 *       directoryName             [4]  Name,
 *       ediPartyName              [5]  EDIPartyName,
 *       uniformResourceIdentifier [6]  IA5String,
 *       iPAddress                 [7]  OCTET STRING,
 *       registeredID              [8]  OBJECT IDENTIFIER }
 *
 *  OtherName ::= SEQUENCE {
 *       type-id    OBJECT IDENTIFIER,
 *       value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 *  EDIPartyName ::= SEQUENCE {
 *       nameAssigner            [0]     DirectoryString OPTIONAL,
 *       partyName               [1]     DirectoryString }
 *
 */
#define NAME_TYPE_rfc822Name     0x81
#define NAME_TYPE_dNSName        0x82
#define NAME_TYPE_URI            0x86
#define NAME_TYPE_iPAddress      0x87
#define NAME_TYPE_registeredID   0x88
#define NAME_TYPE_otherName      0xa0
#define NAME_TYPE_x400Address    0xa3
#define NAME_TYPE_directoryName  0xa4
#define NAME_TYPE_ediPartyName   0xa5

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, empty, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (\result == 0) ==> (0 <= *empty <= 1);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten, *empty;
  @*/
static int parse_GeneralName(const u8 *buf, u32 len, u32 *eaten, int *empty)
{
	u32 remain = 0, name_len = 0, name_hdr_len = 0, grabbed = 0;
	u8 name_type;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len < 2) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain = len;

	/*
	 * We expect the id for current name to be encoded on
	 * a single byte, i.e. we expect its MSB to be set.
	 */
	name_type = buf[0];
	if (!(name_type & 0x80)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	switch (name_type) {
	case NAME_TYPE_rfc822Name: /* 0x81 - rfc822Name - IA5String */
	case NAME_TYPE_dNSName:    /* 0x82 - dNSName - IA5String */
	case NAME_TYPE_URI:        /* 0x86 - uniformResourceIdentifier - IA5String */
		buf += 1;
		remain -= 1;

		ret = get_length(buf, remain, &name_len, &grabbed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		buf += grabbed;
		remain -= grabbed;

		if (name_len > remain) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		ret = check_ia5_string(buf, name_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/* Now, do some more specific checks */
		switch (name_type) {
		case NAME_TYPE_rfc822Name: /* rfc822Name - IA5String */

			/* FIXME! We should do more parsing on that one */

			break;
		case NAME_TYPE_dNSName: /* dNSName - IA5String */

			/* FIXME! We should do more parsing on that one */
			/*
			 * From section 4.2.1.6 of RFC5280:
			 * The name MUST be in the "preferred name syntax",
			 * as specified by Section 3.5 of [RFC1034] and as
			 * modified by Section 2.1 of [RFC1123].
			 */
			break;
		case NAME_TYPE_URI: /* uniformResourceIdentifier - IA5String */

			/* FIXME! We should do more parsing on that one */

			break;
		default:
			break;
		}

		remain -= name_len;
		buf += name_len;
		*eaten = name_len + grabbed + 1;
		*empty = !name_len;
		/*@ assert *eaten > 1; */
		break;

	case NAME_TYPE_iPAddress: /* 0x87 - iPaddress - OCTET STRING */
		buf += 1;
		remain -= 1;

		ret = get_length(buf, remain, &name_len, &grabbed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		buf += grabbed;
		remain -= grabbed;

		if (name_len > remain) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/* FIXME! Check size is 4, resp. 16, for IPv4, resp. IPv6. */

		remain -= name_len;
		buf += name_len;
		*eaten = name_len + grabbed + 1;
		*empty = !name_len;
		/*@ assert *eaten > 1; */
		break;

	case NAME_TYPE_otherName: /* 0xa0 - otherName - OtherName */
		/* FIXME! unsupported */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;

	case NAME_TYPE_x400Address: /* 0xa3 - x400Address - ORAddress */
		/* FIXME! unsupported */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;

	case NAME_TYPE_directoryName: /* 0xa4 - directoryName - Name */
		ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 4,
				   &name_hdr_len, &name_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += name_hdr_len;
		remain = name_len;

		ret = parse_x509_Name(buf, remain, &grabbed, empty);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += grabbed;
		remain -= grabbed;

		if (remain) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		*eaten = name_hdr_len + name_len;
		/*@ assert *eaten > 1; */
		break;

	case NAME_TYPE_ediPartyName: /* 0xa5 - ediPartyName - EDIPartyName */
		/* FIXME! unsupported */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;

	case NAME_TYPE_registeredID: /* 0x88 - registeredID - OBJECT IDENTIFIER */
		/* FIXME! unsupported */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;

	default:
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;
	}

	/*@ assert *eaten > 1; */
	ret = 0;

out:
	return ret;
}

/* GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_GeneralNames(const u8 *buf, u32 len, tag_class exp_class,
			      u32 exp_type, u32 *eaten)
{
	u32 remain, parsed = 0, hdr_len = 0, data_len = 0;
	int ret, unused = 0;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_id_len(buf, len, exp_class, exp_type,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	/*@
	  @ loop assigns ret, buf, remain, parsed, unused;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop variant remain;
	  @ */
	while (remain) {
		ret = parse_GeneralName(buf, remain, &parsed, &unused);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= parsed;
		buf += parsed;
	}

	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_AccessDescription(const u8 *buf, u32 len, u32 *eaten)
{
	const u8 id_ad_caIssuers_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
					   0x05, 0x07, 0x30, 0x01 };
	const u8 id_ad_ocsp_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
				      0x05, 0x07, 0x30, 0x02 };
	u32 remain, hdr_len = 0, data_len = 0, oid_len = 0;
	u32 al_len = 0, saved_ad_len = 0;
	int ret, found, unused;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain = len;

	ret = parse_id_len(buf, remain,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	saved_ad_len = hdr_len + data_len;
	/*@ assert saved_ad_len <= len ; */
	remain -= hdr_len;
	/*@ assert remain >= data_len ; */
	buf += hdr_len;

	/* accessMethod is an OID */
	ret = parse_OID(buf, data_len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We only support the two OID that are reference in the RFC,
	 * i.e. id-ad-caIssuers and id-ad-ocsp.
	 */
	found = 0;

	if (oid_len == sizeof(id_ad_caIssuers_oid)) {
		found = !bufs_differ(buf, id_ad_caIssuers_oid, oid_len);
	}

	if ((!found) && (oid_len == sizeof(id_ad_ocsp_oid))) {
		found = !bufs_differ(buf, id_ad_ocsp_oid, oid_len);
	}

	if (!found) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += oid_len;
	remain -= oid_len;
	data_len -= oid_len;
	/*@ assert remain >= data_len ; */

	/* accessLocation is a GeneralName */
	ret = parse_GeneralName(buf, data_len, &al_len, &unused);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * FIXME! I guess we could do some specific parsing on the
	 * content of the generalName based on what is described
	 * in section 4.2.2.1 of RFC 5280.
	 */

	buf += al_len;
	/*@ assert remain >= data_len >= al_len; */
	remain -= al_len;
	data_len -= al_len;

	if (data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = saved_ad_len;
	/*@ assert *eaten <= len ; */
	ret = 0;

out:
	return ret;
}

/*
 * 4.2.2.1 - Certificate Authority Information Access
 *
 *    id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
 *
 *    AuthorityInfoAccessSyntax  ::=
 *            SEQUENCE SIZE (1..MAX) OF AccessDescription
 *
 *    AccessDescription  ::=  SEQUENCE {
 *            accessMethod          OBJECT IDENTIFIER,
 *            accessLocation        GeneralName  }
 *
 *    id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
 *
 *    id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
 *
 *    id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 *
 *  GeneralName ::= CHOICE {
 *       otherName                 [0]  AnotherName,
 *       rfc822Name                [1]  IA5String,
 *       dNSName                   [2]  IA5String,
 *       x400Address               [3]  ORAddress,
 *       directoryName             [4]  Name,
 *       ediPartyName              [5]  EDIPartyName,
 *       uniformResourceIdentifier [6]  IA5String,
 *       iPAddress                 [7]  OCTET STRING,
 *       registeredID              [8]  OBJECT IDENTIFIER }
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (critical != 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_AIA(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
			 const u8 *cert, u32 off, u32 len, int critical)
{
	u32 hdr_len = 0, data_len = 0, remain;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * 4.2.2.1 of RFC5280 has "Conforming CAs MUST mark this
	 * extension as non-critical
	 */
	if (critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain = len;

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain -= hdr_len;

	/* We do expect sequence to exactly match the length */
	if (remain != data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * Empty AIA extensions are not authorized (AIA is a non empty sequence
	 * of AccessDescription structures.
	 */
	if (!remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * Iterate on AccessDescription structures: each is
	 * a sequence containing an accessMethod (an OID)
	 * and an accessLocation (a GeneralName).
	 */
	/*@
	  @ loop assigns ret, buf, remain;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop variant remain;
	  @ */
	while (remain) {
		u32 parsed = 0;

		ret = parse_AccessDescription(buf, remain, &parsed);
		if (ret) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= parsed;
		buf += parsed;
	}

	ret = 0;

out:
	return ret;
}

/* 4.2.1.1. Authority Key Identifier
 *
 * The identification MAY be based on either the key identifier (the subject
 * key identifier in the issuer's certificate) or the issuer name and serial
 * number.
 *
 *   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 *
 *   AuthorityKeyIdentifier ::= SEQUENCE {
 *      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 *      -- authorityCertIssuer and authorityCertSerialNumber MUST both
 *      -- be present or both be absent
 *
 *   KeyIdentifier ::= OCTET STRING
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->aki_has_keyIdentifier,
	    ctx->aki_keyIdentifier_start,
	    ctx->aki_keyIdentifier_len,
	    ctx->aki_has_generalNames_and_serial,
	    ctx->aki_generalNames_start,
	    ctx->aki_generalNames_len,
	    ctx->aki_serial_start,
	    ctx->aki_serial_len,
	    ctx->has_aki;
  @*/
static int parse_ext_AKI(cert_parsing_ctx *ctx,
			 const u8 *cert, u32 off, u32 len, int critical)
{
	u32 hdr_len = 0, data_len = 0;
	const u8 *buf = cert + off;
	u32 key_id_hdr_len = 0, key_id_data_len = 0, key_id_data_off = 0;
	u32 gen_names_off = 0, gen_names_len = 0;
	u32 cert_serial_off = 0, cert_serial_len = 0;
	u32 remain;
	u32 parsed = 0;
	int ret, has_keyIdentifier = 0, has_gen_names_and_serial = 0;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * As specified in section 4.2.1.1. of RFC 5280, it is recommended
	 * for conforming CA not to set the critical bit for AKI extension
	 */
	if (critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check we are indeed dealing w/ a sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We should now find a KeyIdentifier or/and a couple of
	 * (GeneralNames, and CertificateSerialNumber).
	 */

	/*
	 * First, the KeyIdentifier if present (KeyIdentifier ::= OCTET STRING)
	 */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
			   &key_id_hdr_len, &key_id_data_len);
	if (!ret) {
		/* An empty KeyIdentifier does not make any sense. Drop it! */
		if (!key_id_data_len) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		key_id_data_off = off + key_id_hdr_len;
		buf += key_id_hdr_len + key_id_data_len;
		off += key_id_hdr_len + key_id_data_len;
		remain -= key_id_hdr_len + key_id_data_len;
		has_keyIdentifier = 1;
	}


	/*
	 * See if a (GeneralNames, CertificateSerialNumber) couple follows.
	 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName. We do
	 * not accept one w/o the other.
	 */
	ret = parse_GeneralNames(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
				 &parsed);
	if (!ret) {
		gen_names_off = off;
		gen_names_len = parsed;

		buf += parsed;
		off += parsed;
		remain -= parsed;

		/* CertificateSerialNumber ::= INTEGER */
		ret = parse_AKICertSerialNumber(ctx, cert, off, remain,
						CLASS_CONTEXT_SPECIFIC, 2,
						&cert_serial_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		/*@ assert cert_serial_len > 2; */

		has_gen_names_and_serial = 1;
		cert_serial_off = off;

		buf += cert_serial_len;
		off += cert_serial_len;
		remain -= cert_serial_len;
	}

	/* Nothing should remain behind */
	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Only populate context when we know everything is ok. */
	ctx->aki_has_keyIdentifier = has_keyIdentifier;
	/*@ assert \initialized(&ctx->aki_has_keyIdentifier); */
	if (ctx->aki_has_keyIdentifier) {
		ctx->aki_keyIdentifier_start = key_id_data_off;
		/*@ assert \initialized(&ctx->aki_keyIdentifier_start); */
		ctx->aki_keyIdentifier_len = key_id_data_len;
		/*@ assert \initialized(&ctx->aki_keyIdentifier_len); */
	}
	ctx->aki_has_generalNames_and_serial = has_gen_names_and_serial;
	/*@ assert \initialized(&ctx->aki_has_generalNames_and_serial); */
	if (ctx->aki_has_generalNames_and_serial) {
		ctx->aki_generalNames_start = gen_names_off;
		/*@ assert \initialized(&ctx->aki_generalNames_start); */
		ctx->aki_generalNames_len = gen_names_len;
		/*@ assert \initialized(&ctx->aki_generalNames_len); */
		ctx->aki_serial_start = cert_serial_off + 2;  /* 2 bytes long hdr for a valid SN */
		/*@ assert \initialized(&ctx->aki_serial_start); */
		ctx->aki_serial_len = cert_serial_len - 2;
		/*@ assert \initialized(&ctx->aki_serial_len); */
	}
	ctx->has_aki = 1;
	/*@ assert \initialized(&ctx->has_aki); */
	ret = 0;

out:
	return ret;
}

/*
 * 4.2.1.2. Subject Key Identifier
 *
 * SubjectKeyIdentifier ::= KeyIdentifier
 * KeyIdentifier ::= OCTET STRING
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx,cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_ski,
	    ctx->ski_start,
	    ctx->ski_len;
  @*/
static int parse_ext_SKI(cert_parsing_ctx *ctx,
			 const u8 *cert, u32 off, u32 len, int critical)
{
	u32 key_id_hdr_len = 0, key_id_data_len = 0;
	const u8 *buf = cert + off;
	u32 remain;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	remain = len;

	/*
	 * As specified in section 4.2.1.1. of RFC 5280, conforming CA
	 * must mark this extension as non-critical.
	 */
#ifdef TEMPORARY_LAXIST_SKI_CRITICAL_FLAG_SET
	(void)critical;
#else
	if (critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
#endif

	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING,
			   &key_id_hdr_len, &key_id_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len != (key_id_hdr_len + key_id_data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* An empty KeyIdentifier does not make any sense. Drop it! */
	if (!key_id_data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain -= key_id_hdr_len + key_id_data_len;
	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->has_ski = 1;
	ctx->ski_start = off + key_id_hdr_len;
	ctx->ski_len = key_id_data_len;
	ret = 0;

out:
	return ret;
}

/*
 * X.509 certificates includes 2 definitions of named bit list which
 * both define 9 flags: KeyUsage and ReasonFlags. For that reason, most
 * of the decoding logic for the instances of this types (keyUsage
 * extension, CRLDP and FreshestCRL) can be done in a single location.
 *
 * Note that the function enforces that at least one bit is set in the
 * nit named bit list, as explicitly required at least for Key Usage.
 * This is in sync with what is given in Appendix B of RFC 5280:
 * "When DER encoding a named bit list, trailing zeros MUST be omitted.
 * That is, the encoded value ends with the last named bit that is set
 * to one."
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \separated(val, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *val;
  @*/
static int parse_nine_bit_named_bit_list(const u8 *buf, u32 len, u16 *val)
{
	u8 k, non_signif;
	int ret;

	/*
	 * Initial content octet is required. It provides the number of
	 * non-significative bits at the end of the last bytes carrying
	 * the bitstring value.
	 */
	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* ... and it must be in the range [0,7]. */
	if (buf[0] & 0xf8) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We encode 9 bits of information in a named bit list bitstring.
	 * With the initial octet of the content octets (encoding the number
	 * of unused bits in the final octet), the whole content octets
	 * should be made of 1, 2 or 3 bytes.
	 */
	switch (len) {
	case 1: /* 1 byte giving number of unused bits - no following bytes */
		if (buf[0] != 0) {
			/*
			 * The number of non-significative bits is non-zero
			 * but no bits are following. This is invalid.
			 */
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		} else {
			/*
			 * Last paragraph of section 4.2.1.3 of RFC 5280 has
			 * "When the keyUsage extension appears in a
			 * certificate, at least one of the bits
			 * MUST be set to 1.". Regarding ReasonFlags, this
			 * is not explictly stated but would not make sense
			 * either.
			 */
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		break;

	case 2: /* 1 byte giving number of unused bits - 1 following byte */
		/*
		 * Last paragraph of section 4.2.1.3 of RFC 5280 has
		 * "When the keyUsage extension appears in a
		 * certificate, at least one of the bits
		 * MUST be set to 1". Regarding ReasonFlags, this would
		 * not make sense either to have an empty list.
		 */
		if (buf[1] == 0) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * Now that we are sure at least one bit is set, we can see
		 * which one is the last one set to verify it matches what
		 * the byte giving the number of unused bits tells us. When
		 * we are dealing w/ non-significative bits, they should be
		 * set to 0 in the byte (11.2.1 of X.690).
		 * Additionally, keyUsage type is a NamedBitList-based
		 * bitstring, and for that reason X.680 clause 11.2.2 requires
		 * "the bitstring shall have all trailing 0 bits removed
		 * before it is encoded". This is also the conclusion of
		 * http://www.ietf.org/mail-archive/web/pkix/current/
		 * msg10424.html. This is also explicitly stated in Appendix B
		 * of RFC5280: "When DER encoding a named bit list, trailing
		 * zeros MUST be omitted.  That is, the encoded value ends with
		 * the last named bit that is set to one."
		 */

		non_signif = 0;

		/*@
		  @ loop assigns k, non_signif;
		  @ loop variant (8 - k);
		  @*/
		for (k = 0; k < 8; k++) {
			if ((buf[1] >> k) & 0x1) {
				non_signif = k;
				break;
			}
		}

		if (buf[0] != non_signif) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/* Revert bits to provide a usable value to caller */
		*val = 0;
		/*@
		  @ loop invariant 0 <= k <= 8;
		  @ loop assigns k, *val;
		  @ loop variant (8 - k);
		  @*/
		for (k = 0; k < 8; k++) {
			*val |= ((buf[1] >> k) & 0x1) << (7 - k);
		}

		break;

	case 3: /* 1 byte for unused bits - 2 following bytes */
		/*
		 * keyUsage and ReasonFlags support at most 9 bits. When the
		 * named bit list bitstring is made of 1 byte giving unused
		 * bits and 2 following bytes, this means the 9th bit (i.e.
		 * bit 8, decipherOnly) is asserted.
		 * Because of that, the value of the byte giving the number
		 * of unused bits is necessarily set to 7.
		 */
		if ((buf[0] != 7) || (buf[2] != 0x80)) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * Revert bits to provide a usable value to caller,
		 * working on first byte's bits and then on single
		 * MSB from second byte.
		 */
		*val = 0;
		/*@
		  @ loop invariant 0 <= k <= 8;
		  @ loop assigns k, *val;
		  @ loop variant (8 - k);
		  @*/
		for (k = 0; k < 8; k++) {
			*val |= ((buf[1] >> k) & 0x1) << (7 - k);
		}
		*val |= buf[2] >> 7;
		break;

	default: /* too many bytes for encoding 9 poor bits */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/* 4.2.1.3. Key Usage
 *
 * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
 *
 * KeyUsage ::= BIT STRING {
 *      digitalSignature        (0),
 *      nonRepudiation          (1), -- recent editions of X.509 have
 *                           -- renamed this bit to contentCommitment
 *      keyEncipherment         (2),
 *      dataEncipherment        (3),
 *      keyAgreement            (4),
 *      keyCertSign             (5),
 *      cRLSign                 (6),
 *      encipherOnly            (7),
 *      decipherOnly            (8) }
 *
 */

/*
 * Masks for keyusage bits. Those masks are only usable on values
 * returned by parse_nine_bit_named_bit_list(), i.e. reversed
 * bits. Those not already used in the code are commented to avoid
 * unused macros and make clang compiler happy.
 */
//#define KU_digitalSignature  0x0001
//#define KU_nonRepudiation    0x0002
//#define KU_keyEncipherment   0x0004
//#define KU_dataEncipherment  0x0008
#define KU_keyAgreement      0x0010
#define KU_keyCertSign       0x0020
#define KU_cRLSign           0x0040
#define KU_encipherOnly      0x0080
#define KU_decipherOnly      0x0100

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_keyUsage,
	    ctx->keyCertSign_set,
	    ctx->cRLSign_set;
  @*/
static int parse_ext_keyUsage(cert_parsing_ctx *ctx,
			      const u8 *cert, u32 off, u32 len,
			      int ATTRIBUTE_UNUSED critical)
{
	u32 hdr_len = 0, data_len = 0;
	u16 val = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

       /*
	 * As specified in section 4.2.1.3 of RFC 5280, when the extension
	 * is present, "conforming CAs SHOULD mark this extension as
	 * critical." For that reason, and because various CA emit certificates
	 * with critical bit not set, we do not enforce critical bit value.
	 */

	/* Check we are indeed dealing w/ a bit string */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
				   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	len -= hdr_len;

	/*
	 * As expected in section 4.2.1.3 of RFC 5280, the function will
	 * enforce that at least one bit is set : "When the keyUsage extension
	 * appears in a certificate, at least one of the bits MUST be set to 1"
	 */
	ret = parse_nine_bit_named_bit_list(buf, data_len, &val);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * Section 4.2.1.3 of RFC 5280 has: "The meaning of the decipherOnly
	 * bit is undefined in the absence of the keyAgreement bit". We
	 * consider it invalid to have the former but not the latter.
	 */
	if ((val & KU_decipherOnly) && !(val & KU_keyAgreement)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * Section 4.2.1.3 of RFC 5280 has: "The meaning of the decipherOnly
	 * bit is undefined in the absence of the keyAgreement bit". We
	 * consider it invalid to have the former but not the latter.
	 */
	if ((val & KU_encipherOnly) && !(val & KU_keyAgreement)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->has_keyUsage = 1;
	ctx->keyCertSign_set = !!(val & KU_keyCertSign);
	ctx->cRLSign_set = !!(val & KU_cRLSign);

	ret = 0;

out:
	return ret;
}

/* CPSuri ::= IA5String */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten,buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_CPSuri(const u8 *buf, u32 len, u32 *eaten)
{
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_ia5_string(buf, len, 1, 65534);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = len;

	ret = 0;

out:
	return ret;
}

/*
 *     DisplayText ::= CHOICE {
 *          ia5String        IA5String      (SIZE (1..200)),
 *          visibleString    VisibleString  (SIZE (1..200)),
 *          bmpString        BMPString      (SIZE (1..200)),
 *          utf8String       UTF8String     (SIZE (1..200)) }
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_DisplayText(const u8 *buf, u32 len, u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0;
	u8 str_type;
	int ret = -1;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	str_type = buf[0];

	switch (str_type) {
	case STR_TYPE_UTF8_STRING:    /* UTF8String */
	case STR_TYPE_IA5_STRING:     /* IA5String */
	case STR_TYPE_VISIBLE_STRING: /* VisibileString */
	case STR_TYPE_BMP_STRING:     /* BMPString */
		ret = parse_id_len(buf, len, CLASS_UNIVERSAL, str_type,
				   &hdr_len, &data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += hdr_len;

		switch (str_type) {
		case STR_TYPE_UTF8_STRING:
			ret = check_utf8_string(buf, data_len);
			if (ret) {
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}
			break;
		case STR_TYPE_IA5_STRING:
			ret = check_ia5_string(buf, data_len);
			if (ret) {
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}
			break;
		case STR_TYPE_VISIBLE_STRING:
			ret = check_visible_string(buf, data_len);
			if (ret) {
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}
			break;
		case STR_TYPE_BMP_STRING:
			ret = check_bmp_string(buf, data_len);
			if (ret) {
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}
			break;
		default:
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
			break;
		}

		*eaten = hdr_len + data_len;

		break;
	default:
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;
	}

out:
	return ret;
}

/*
 *     NoticeReference ::= SEQUENCE {
 *          organization     DisplayText,
 *          noticeNumbers    SEQUENCE OF INTEGER }
 *
 *     DisplayText ::= CHOICE {
 *          ia5String        IA5String      (SIZE (1..200)),
 *          visibleString    VisibleString  (SIZE (1..200)),
 *          bmpString        BMPString      (SIZE (1..200)),
 *          utf8String       UTF8String     (SIZE (1..200)) }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_NoticeReference(const u8 *buf, u32 len, u32 *eaten)
{
	u32 remain, parsed = 0, saved_len = 0, hdr_len = 0, data_len = 0;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain = len;

	/* NoticeReference is a sequence */
	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	saved_len = hdr_len + data_len;
	remain = data_len;
	buf += hdr_len;

	/*
	 * First element of the sequence is the organization (of type
	 * DisplayText)
	 */
	ret = parse_DisplayText(buf, remain, &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain -= parsed;
	buf += parsed;

	/*
	 * Second element is the noticeNumbers, i.e. a sequence of
	 * integers.
	 */
	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain -= hdr_len;
	buf += hdr_len;

	/* Advertised data in the sequence must exactly match what remains */
	if (remain != data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* The sequence contains integers */
	/*@
	  @ loop assigns ret, buf, remain, parsed, hdr_len, data_len;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop variant remain;
	  @ */
	while (remain) {
		/* Verify the integer is encoded as it should */
		ret = parse_integer(buf, remain,
				    CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
				    &hdr_len, &data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		parsed = hdr_len + data_len;
		remain -= parsed;
		buf += parsed;
	}

	*eaten = saved_len;

	ret = 0;

out:
	return ret;
}

/*
 *     UserNotice ::= SEQUENCE {
 *          noticeRef        NoticeReference OPTIONAL,
 *          explicitText     DisplayText OPTIONAL }
 *
 *     NoticeReference ::= SEQUENCE {
 *          organization     DisplayText,
 *          noticeNumbers    SEQUENCE OF INTEGER }
 *
 *     DisplayText ::= CHOICE {
 *          ia5String        IA5String      (SIZE (1..200)),
 *          visibleString    VisibleString  (SIZE (1..200)),
 *          bmpString        BMPString      (SIZE (1..200)),
 *          utf8String       UTF8String     (SIZE (1..200)) }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_UserNotice(const u8 *buf, u32 len, u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0, remain = 0, parsed = 0;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain = len;

	/* USerNotice is a sequence */
	ret = parse_id_len(buf, remain, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain -= hdr_len;
	buf += hdr_len;

	/* Having an empty sequence is considered invalid */
	if (!data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* First element (if present) is a noticeRef of type NoticeReference */
	ret = parse_NoticeReference(buf, remain, &parsed);
	if (!ret) {
		remain -= parsed;
		buf += parsed;
	}

	/* Second element (if present) is an explicitText of type DisplayText */
	ret = parse_DisplayText(buf, remain, &parsed);
	if (!ret) {
		remain -= parsed;
		buf += parsed;
	}

	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/*
 *   PolicyQualifierInfo ::= SEQUENCE {
 *        policyQualifierId  PolicyQualifierId,
 *        qualifier          ANY DEFINED BY policyQualifierId }
 *
 *   -- policyQualifierIds for Internet policy qualifiers
 *
 *   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
 *   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
 *   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
 *
 *   PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_policyQualifierInfo(const u8 *buf, u32 len, u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0, oid_len = 0, remain = 0;
	u8 id_qt_cps_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
			       0x07, 0x02, 0x01 };
	u8 id_qt_unotice_oid[] = { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
				   0x07, 0x02, 0x02 };
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* It's a sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain = data_len;
	buf += hdr_len;

	/*
	 * First element of the sequence (policyQualifierId) is an OID
	 * which can either take a value of id-qt-cps or id-qt-unotice.
	 */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if ((oid_len == sizeof(id_qt_cps_oid)) &&
	    !bufs_differ(buf, id_qt_cps_oid, oid_len)) { /* id-qt-cps */
		u32 cpsuri_len = 0;

		buf += oid_len;
		remain -= oid_len;

		ret = parse_CPSuri(buf, remain, &cpsuri_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= cpsuri_len;
		buf += cpsuri_len;

	} else if ((oid_len == sizeof(id_qt_unotice_oid)) &&
	    !bufs_differ(buf, id_qt_unotice_oid, oid_len)) { /* id-qt-unotice */
		u32 cpsunotice_len = 0;

		buf += oid_len;
		remain -= oid_len;

		ret = parse_UserNotice(buf, remain, &cpsunotice_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= cpsunotice_len;
		buf += cpsunotice_len;

	} else {                                        /* unsupported! */
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/*
 *   PolicyInformation ::= SEQUENCE {
 *        policyIdentifier   CertPolicyId,
 *        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                                PolicyQualifierInfo OPTIONAL }
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten,buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_PolicyInformation(const u8 *buf, u32 len, u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0, oid_len = 0, saved_pi_len, remain;
	int ret;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	saved_pi_len = hdr_len + data_len;

	remain = data_len;
	buf += hdr_len;

	/* policyIdentifier is a CertPolicyId, i.e. an OID */
	ret = parse_OID(buf, remain, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain -= oid_len;
	buf += oid_len;

	/* policyQualifiers is optional */
	if (remain) {
		/* policyQualifiers is a sequence */
		ret = parse_id_len(buf, remain,
				   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
				   &hdr_len, &data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= hdr_len;
		buf += hdr_len;

		/* Nothing should remain after policyQualifiers */
		if (remain != data_len) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * Let's parse each PolicyQualifierInfo in the
		 * policyQualifiers sequence
		 */
		/*@
		  @ loop assigns ret, buf, remain;
		  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
		  @ loop variant remain;
		  @ */
		while (remain) {
			u32 pqi_len = 0;

			ret = parse_policyQualifierInfo(buf, remain, &pqi_len);
			if (ret) {
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			remain -= pqi_len;
			buf += pqi_len;
		}
	}

	*eaten = saved_pi_len;

	/*
	 * FIXME! At that point, we should verify we know the OID
	 * (policyIdentifier) and the associated optional
	 * content is indeed valid.
	 */

	ret = 0;

out:
	return ret;
}


/* 4.2.1.4. Certificate Policies
 *
 * id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
 *
 *   anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }
 *
 *   certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 *
 *   PolicyInformation ::= SEQUENCE {
 *        policyIdentifier   CertPolicyId,
 *        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                                PolicyQualifierInfo OPTIONAL }
 *
 *   CertPolicyId ::= OBJECT IDENTIFIER
 *
 *   PolicyQualifierInfo ::= SEQUENCE {
 *        policyQualifierId  PolicyQualifierId,
 *        qualifier          ANY DEFINED BY policyQualifierId }
 *
 *   -- policyQualifierIds for Internet policy qualifiers
 *
 *   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
 *   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
 *   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
 *
 *   PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 *
 *   Qualifier ::= CHOICE {
 *        cPSuri           CPSuri,
 *        userNotice       UserNotice }
 *
 *   CPSuri ::= IA5String
 *
 *   UserNotice ::= SEQUENCE {
 *        noticeRef        NoticeReference OPTIONAL,
 *        explicitText     DisplayText OPTIONAL }
 *
 *   NoticeReference ::= SEQUENCE {
 *        organization     DisplayText,
 *        noticeNumbers    SEQUENCE OF INTEGER }
 *
 *   DisplayText ::= CHOICE {
 *        ia5String        IA5String      (SIZE (1..200)),
 *        visibleString    VisibleString  (SIZE (1..200)),
 *        bmpString        BMPString      (SIZE (1..200)),
 *        utf8String       UTF8String     (SIZE (1..200)) }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_certPolicies(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
				  const u8 *cert, u32 off, u32 len,
				  int ATTRIBUTE_UNUSED critical)
{
	u32 remain = 0, data_len = 0, hdr_len = 0, eaten = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * FIXME!
	 *
	 * This one will be a pain to deal with if we decide
	 * to support the full version, i.e. non empty sequence
	 * for policyQualifiersOID. RFC 5280 has:
	 *
	 *  To promote interoperability, this profile RECOMMENDS that policy
	 *  information terms consist of only an OID.	 Where an OID alone is
	 *  insufficient, this profile strongly recommends that the use of
	 *  qualifiers be limited to those identified in this section.  When
	 *  qualifiers are used with the special policy anyPolicy, they MUST be
	 *  limited to the qualifiers identified in this section.  Only those
	 *  qualifiers returned as a result of path validation are considered.
	 *
	 */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's now check each individual PolicyInformation sequence */
	/*@
	  @ loop assigns ret, buf, remain, eaten, off;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop invariant (off + remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @ */
	while (remain) {
		ret = parse_PolicyInformation(buf, remain, &eaten);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= eaten;
		off += eaten;
		buf += eaten;
	}

	ret = 0;

out:
	return ret;
}

/*
 * 4.2.1.5. Policy Mappings
 *
 * id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 }
 *
 * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx,cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_policyMapping(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
				   const u8 *cert, u32 off, u32 len,
				   int critical)
{
	u32 remain = 0, data_len = 0, hdr_len = 0, eaten = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * As specified in section 4.2.1.5. of RFC 5280, "conforming CAs
	 * SHOULD mark this extension as critical".
	 */
	if (!critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's first check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's now check each sequence of {issuer,subject}DomainPolicy pair */
	/*@
	  @ loop assigns ret, buf, remain, hdr_len, data_len, eaten, off;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop invariant (off + remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @ */
	while (remain) {
		ret = parse_id_len(buf, remain,
				   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
				   &hdr_len, &data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += hdr_len;
		off += hdr_len;
		remain -= hdr_len;

		/* issuerDomainPolicy (an OID)*/
		ret = parse_OID(buf, data_len, &eaten);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += eaten;
		off += eaten;
		remain -= eaten;
		data_len -= eaten;

		/* subjectDomainPolicy (an OID) */
		ret = parse_OID(buf, data_len, &eaten);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		data_len -= eaten;
		if (data_len) {
			/*
			 * Nothing should follow the two OIDs
			 * in the sequence.
			 */
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += eaten;
		off += eaten;
		remain -=  eaten;
	}

	ret = 0;

out:
	return ret;
}


/*  4.2.1.6. Subject Alternative Name
 *
 *   id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
 *
 *   SubjectAltName ::= GeneralNames
 *
 *   GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 *   GeneralName ::= CHOICE {
 *        otherName                       [0]     OtherName,
 *        rfc822Name                      [1]     IA5String,
 *        dNSName                         [2]     IA5String,
 *        x400Address                     [3]     ORAddress,
 *        directoryName                   [4]     Name,
 *        ediPartyName                    [5]     EDIPartyName,
 *        uniformResourceIdentifier       [6]     IA5String,
 *        iPAddress                       [7]     OCTET STRING,
 *        registeredID                    [8]     OBJECT IDENTIFIER }
 *
 *   OtherName ::= SEQUENCE {
 *        type-id    OBJECT IDENTIFIER,
 *        value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 *   EDIPartyName ::= SEQUENCE {
 *        nameAssigner            [0]     DirectoryString OPTIONAL,
 *        partyName               [1]     DirectoryString }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_san,
	    ctx->san_critical;
  @*/
static int parse_ext_SAN(cert_parsing_ctx *ctx,
			 const u8 *cert, u32 off, u32 len,
			 int critical)
{
	u32 data_len = 0, hdr_len = 0, remain = 0, eaten = 0;
	const u8 *buf = cert + off;
	int ret, empty_gen_name;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* Let's first check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * As specified in section 4.2.1.6. of RFC 5280, "if the subjectAltName
	 * extension is present, the sequence MUST contain at least one entry.
	 */
	if (!data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@
	  @ loop assigns ret, buf, remain, eaten, empty_gen_name;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop variant remain;
	  @ */
	while (remain) {
		empty_gen_name = 0;
		ret = parse_GeneralName(buf, remain, &eaten, &empty_gen_name);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * Section 4.2.16 of RFC 5280 has "Unlike the subject field,
		 * conforming CAs MUST NOT issue certificates with
		 * subjectAltNames containing empty GeneralName fields.
		 */
		if (empty_gen_name) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * RFC5280 has: "When the subjectAltName extension contains an
		 * iPAddress, the address MUST be stored in the octet string in
		 * "network byte order", as specified in [RFC791].  The least
		 * significant bit (LSB) of each octet is the LSB of the
		 * corresponding byte in the network address.  For IP version
		 * 4, as specified in [RFC791], the octet string MUST contain
		 * exactly four octets. For IP version 6, as specified in
		 * [RFC2460], the octet string MUST contain exactly sixteen
		 * octets.
		 */
		if (buf[0] == NAME_TYPE_iPAddress) {
			switch (eaten) {
			case 6: /* id/len/IPv4(4 bytes) */
				break;
			case 18: /* id/len/IPv6(16 bytes) */
				break;
			default: /* invalid */
				ret = -__LINE__;
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
				break;
			}
		}

		remain -= eaten;
		buf += eaten;
	}

	/*
	 * Now that we know the extension is valid, let's record some
	 * useful info.
	 */
	ctx->has_san = 1;
	ctx->san_critical = critical;

	ret = 0;

out:
	return ret;
}

/* 4.2.1.7. Issuer Alternative Name */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_IAN(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
			 const u8 *cert, u32 off, u32 len,
			 int ATTRIBUTE_UNUSED critical)
{
	u32 data_len = 0, hdr_len = 0, remain = 0, eaten = 0;
	const u8 *buf = cert + off;
	int ret, unused = 0;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Section 4.2.1.7 of RFC 5280 has "Where present, conforming CAs
	 * SHOULD mark this extension as non-critical."
	 *
	 * FIXME! add a check?
	 */

	/* Let's first check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * As specified in section 4.2.1.6. of RFC 5280, "if the subjectAltName
	 * extension is present, the sequence MUST contain at least one entry.
	 * Unlike the subject field, conforming CAs MUST NOT issue certificates
	 * with subjectAltNames containing empty GeneralName fields.
	 *
	 * The first check is done here.
	 *
	 * FIXME! second check remains to be done. Possibly in adding an additional
	 * out parameter to parse_GeneralName(), to tell if an empty one is
	 * empty. This is because
	 */
	if (!data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@
	  @ loop assigns ret, buf, remain, eaten, unused, off;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop invariant (off + remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @ */
	while (remain) {
		ret = parse_GeneralName(buf, remain, &eaten, &unused);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= eaten;
		off += eaten;
		buf += eaten;
	}

	ret = 0;

out:
	return ret;
}

/*
 * 4.2.1.8. Subject Directory Attributes
 *
 * id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 }
 *
 * SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
 *
 * Attribute ::= SEQUENCE {
 *   type    AttributeType,
 *   values  SET OF AttributeValue
 *   -- at least one value is required --
 * }
 *
 * AttributeType           ::= OBJECT IDENTIFIER
 *
 * AttributeValue          ::= ANY -- DEFINED BY AttributeType
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_subjectDirAttr(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
				    const u8 *cert, u32 off, u32 len,
				    int critical)
{
	u32 hdr_len = 0, data_len = 0, oid_len = 0, remain = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * As specified in section 4.2.1.8. of RFC 5280, conforming CAs
	 * MUST mark this extension as non-critical.
	 */
	if (critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's first check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@
	  @ loop assigns ret, buf, remain, hdr_len, data_len, oid_len, off;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop invariant (off + remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @ */
	while (remain) {
		/* Parse current attribute. Each one is a sequence ... */
		ret = parse_id_len(buf, remain,
				   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
				   &hdr_len, &data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += hdr_len;
		off += hdr_len;
		remain -= hdr_len;

		/* ... containing an OID (AttributeType) */
		ret = parse_OID(buf, data_len, &oid_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/* FIXME! check the value depanding on the OID */

		remain -= data_len;
		off += data_len;
		buf += data_len;
	}

	ret = 0;

out:
	return ret;
}

/* 4.2.1.9. Basic Constraints
 *
 * id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
 *
 * BasicConstraints ::= SEQUENCE {
 *      cA                      BOOLEAN DEFAULT FALSE,
 *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->bc_critical,
	    ctx->ca_true,
	    ctx->pathLenConstraint_set;
  @*/
static int parse_ext_basicConstraints(cert_parsing_ctx *ctx,
				      const u8 *cert, u32 off, u32 len,
				      int critical)
{
	u32 hdr_len = 0, data_len = 0;
	const u8 ca_true_wo_plc[] = { 0x01, 0x01, 0xff };
	const u8 ca_true_w_plc[] = { 0x01, 0x01, 0xff, 0x02, 0x01 };
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/* Record if basicConstraints extension was mared critical */
	ctx->bc_critical = critical;

	/* Let's first check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * Only the following cases are valid/reasonable:
	 *
	 *  1) an empty sequence (cA default to false, resulting in
	 *    no pathLenConstraint): { }
	 *  2) cA is explicitly set to TRUE and no pathLenConstraint
	 *    is enforced. { 0x01, 0x01, 0xff }
	 *  3) cA is explicitly set to TRUE and a pathLenConstraint
	 *    is enforced, in which case it is reasonable to limit
	 *    allowed pathLenConstraint values to [0, 255]:
	 *    { 0x01, 0x01, 0xff, 0x02, 0x01, 0xXX }
	 *
	 * Note:
	 *
	 *  - encoding an explicit FALSE value for cA is invalid
	 *    because this is the default value.
	 *  - providing a pathLenConstraint w/o setting cA boolean
	 *    does not make sense
	 */
	switch (data_len) {
	case 0: /* empty sequence */
		ret = 0;
		break;
	case 3: /* no pathLenConstraint */
		/*
		 * We should indeed find a CA TRUE here. If this is
		 * the case everything is fine.
		 */
		ret = bufs_differ(buf, ca_true_wo_plc, 3);
		if (!ret) {
			ctx->ca_true = 1;
			break;
		}

		/*
		 * Here, we should directly leave w/o spending more
		 * time except if we were instructed to accept
		 * wrongdoing CAs asserting FALSE boolean for CA.
		 */
#ifdef TEMPORARY_LAXIST_CA_BASIC_CONSTRAINTS_BOOLEAN_EXPLICIT_FALSE
		{
			const u8 ca_false_explicit_wo_plc[] = { 0x01, 0x01, 0x00 };

			ret = bufs_differ(buf, ca_false_explicit_wo_plc, 3);
			if (!ret) {
				break;
			}
		}
#endif

		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
		break;
	case 6: /* CA set, pathLenConstraint given ([0,127] allowed) */
		ret = bufs_differ(buf, ca_true_w_plc, 5);
		if (ret) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * Section 4.2.1.9 of RFC 5280 has "Where it appears, the
		 * pathLenConstraint field MUST be greater than or equal
		 * to zero". We check MSB is not set, indicating it is
		 * positive.
		 */
		if (buf[5] & 0x80) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		ctx->ca_true = 1;
		ctx->pathLenConstraint_set = 1;
		break;
	default: /* crap */
		ret = -__LINE__;
		break;
	}

out:
	return ret;
}

/* 4.2.1.10. Name Constraints */


/*
 * Parse GeneralSubtrees structure.
 *
 *    GeneralSubtree ::= SEQUENCE {
 *         base                    GeneralName,
 *         minimum         [0]     BaseDistance DEFAULT 0,
 *         maximum         [1]     BaseDistance OPTIONAL }
 *
 *    BaseDistance ::= INTEGER (0..MAX)
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_GeneralSubtrees(const u8 *buf, u32 len)
{
	u32 hdr_len = 0, remain = 0, grabbed = 0, data_len = 0;
	int ret, unused = 0;

	if ((buf == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	/* base is a GeneralName */
	ret = parse_GeneralName(buf, remain, &grabbed, &unused);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += grabbed;
	remain -= grabbed;

	/*
	 * Section 4.2.1.10 of RFC5280 has "Within this profile, the minimum
	 * and maximum fields are not used with any name forms, thus, the
	 * minimum MUST be zero, ...
	 *
	 * Note: as the minum defaults to 0 in its definition, the field
	 * must be absent (i.e. cannot be present with a value of 0),
	 * as expected in DER encoding (11.5 of X.690 has: "the encoding of
	 * a set value or sequence value shall not include an encoding for
	 * any component value which is equal to its default value.)"
	 */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
			   &hdr_len, &data_len);
	if (!ret) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* ... and maximum MUST be absent." */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
			   &hdr_len, &data_len);
	if (!ret) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Nothing should remain behind */
	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}


/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result < 0 || \result == 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_name_constraints;
  @*/
static int parse_ext_nameConstraints(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len, int critical)
{
	u32 remain = 0, hdr_len = 0, data_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Section 4.2.1.10 of RFC 5280 has "Conforming CAs MUST mark
	 * this extension as critical.
	 */
	if (!critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's first check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &remain);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;

	/*
	 * 4.2.1.10 has: "Conforming CAs MUST NOT issue certificates
	 * where name constraints is an empty sequence
	 */
	if (!remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check if we have a permittedSubtrees structure */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
			   &hdr_len, &data_len);
	if (!ret) {
		buf += hdr_len;
		off += hdr_len;
		remain -= hdr_len;

		ret = parse_GeneralSubtrees(buf, data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += data_len;
		off += data_len;
		remain -= data_len;
	}

	/* Check if we have an excludedSubtrees structure */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
			   &hdr_len, &data_len);
	if (!ret) {
		buf += hdr_len;
		off += hdr_len;
		remain -= hdr_len;

		ret = parse_GeneralSubtrees(buf, data_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += data_len;
		off += data_len;
		remain -= data_len;
	}

	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->has_name_constraints = 1;

	ret = 0;

out:
	return ret;
}

/*
 * 4.2.1.11. Policy Constraints
 *
 * id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
 *
 *  PolicyConstraints ::= SEQUENCE {
 *       requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *       inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 *
 *  SkipCerts ::= INTEGER (0..MAX)
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_policyConstraints(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
				       const u8 *cert, u32 off, u32 len,
				       int critical)
{
	u32 data_len = 0, hdr_len = 0, remain = 0, parsed = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Section 4.2.1.11 of RFC 5280 has "Conforming CAs MUST mark this
	 * extension as critical".
	 */
	if (!critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's first check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * Section 4.2.1.11 of RFC 5280 has "Conforming CAs MUST NOT issue
	 * certificates where policy constraints is an empty sequence".
	 */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	/* Check if we have a requireExplicitPolicy */
	ret = parse_integer(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
			    &hdr_len, &data_len);
	if (!ret) {
		/*
		 * As the value is expected to be a very small integer,
		 * content should be encoded on at most 1 byte, i.e.
		 * 'parsed' value should be 3 (w/ 2 bytes header).
		 */
		parsed = hdr_len + data_len;
		if (parsed != 3) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += parsed;
		off += parsed;
		remain -= parsed;
	}

	/* Check if we have an inhibitPolicyMapping */
	ret = parse_integer(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
			    &hdr_len, &data_len);
	if (!ret) {
		/*
		 * As the value is expected to be a very small integer,
		 * content should be encoded on at most 1 byte, i.e.
		 * 'parsed' value should be 3 (w/ 2 bytes header).
		 */
		parsed = hdr_len + data_len;
		if (parsed != 3) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += parsed;
		off += parsed;
		remain -= parsed;
	}

	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
       return ret;
}

static const u8 _id_kp_anyEKU[] =       { 0x06, 0x08, 0x2b, 0x06,
					  0x01, 0x05, 0x05, 0x07,
					  0x03, 0x00 };
static const u8 _id_kp_serverAuth[] =   { 0x06, 0x08, 0x2b, 0x06,
					  0x01, 0x05, 0x05, 0x07,
					  0x03, 0x01 };
static const u8 _id_kp_clientAuth[] =   { 0x06, 0x08, 0x2b, 0x06,
					  0x01, 0x05, 0x05, 0x07,
					  0x03, 0x02 };
static const u8 _id_kp_codeSigning[] =  { 0x06, 0x08, 0x2b, 0x06,
					  0x01, 0x05, 0x05, 0x07,
					  0x03, 0x03 };
static const u8 _id_kp_emailProt[] =    { 0x06, 0x08, 0x2b, 0x06,
					  0x01, 0x05, 0x05, 0x07,
					  0x03, 0x04 };
static const u8 _id_kp_timeStamping[] = { 0x06, 0x08, 0x2b, 0x06,
					  0x01, 0x05, 0x05, 0x07,
					  0x03, 0x08 };
static const u8 _id_kp_OCSPSigning[] =  { 0x06, 0x08, 0x2b, 0x06,
					  0x01, 0x05, 0x05, 0x07,
					  0x03, 0x09 };
static const u8 _id_kp_ns_SGC[] = {  0x06, 0x09, 0x60, 0x86, 0x48,
				     0x01, 0x86, 0xF8, 0x42, 0x04,
				     0x01  };
static const u8 _id_kp_ms_SGC[] = {  0x06, 0x0A, 0x2B, 0x06, 0x01,
				     0x04, 0x01, 0x82, 0x37, 0x0A,
				     0x03, 0x03,   };


typedef struct {
	const u8 *oid;
	u8 oid_len;
} _kp_oid;

static const _kp_oid known_kp_oids[] = {
	{ .oid = _id_kp_anyEKU,
	  .oid_len = sizeof(_id_kp_anyEKU),
	},
	{ .oid = _id_kp_serverAuth,
	  .oid_len = sizeof(_id_kp_serverAuth),
	},
	{ .oid = _id_kp_clientAuth,
	  .oid_len = sizeof(_id_kp_clientAuth),
	},
	{ .oid = _id_kp_codeSigning,
	  .oid_len = sizeof(_id_kp_codeSigning),
	},
	{ .oid = _id_kp_emailProt,
	  .oid_len = sizeof(_id_kp_emailProt),
	},
	{ .oid = _id_kp_timeStamping,
	  .oid_len = sizeof(_id_kp_timeStamping),
	},
	{ .oid = _id_kp_OCSPSigning,
	  .oid_len = sizeof(_id_kp_OCSPSigning),
	},
	{ .oid = _id_kp_ns_SGC,
	  .oid_len = sizeof(_id_kp_ns_SGC),
	},
	{ .oid = _id_kp_ms_SGC,
	  .oid_len = sizeof(_id_kp_ms_SGC),
	},
};

#define NUM_KNOWN_KP_OIDS (sizeof(known_kp_oids) / sizeof(known_kp_oids[0]))

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_KP_OIDS && \result == &known_kp_oids[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static const _kp_oid * find_kp_by_oid(const u8 *buf, u32 len)
{
	const _kp_oid *found = NULL;
	const _kp_oid *cur = NULL;
	u8 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@ loop unroll NUM_KNOWN_KP_OIDS ;
	  @ loop invariant 0 <= k <= NUM_KNOWN_KP_OIDS;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_KP_OIDS - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_KP_OIDS; k++) {
		int ret;

		cur = &known_kp_oids[k];

		/*@ assert cur == &known_kp_oids[k];*/
		if (cur->oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->oid, buf, cur->oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}

/*
 * 4.2.1.12. Extended Key Usage
 *
 *    id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
 *
 *   ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 *   KeyPurposeId ::= OBJECT IDENTIFIER
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_eku;
  @*/
static int parse_ext_EKU(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
			 const u8 *cert, u32 off, u32 len,
			 int critical)
{
	u32 remain = 0, data_len = 0, hdr_len = 0, oid_len = 0;
	const u8 *buf = cert + off;
	const _kp_oid *kp = NULL;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret || (data_len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Let's now check each individual KeyPurposeId in the sequence */
	/*@
	  @ loop assigns ret, oid_len, kp, buf, remain, off;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop invariant (off + remain) <= MAX_UINT32;
	  @ loop variant remain;
	  @ */
	while (remain) {
		ret = parse_OID(buf, remain, &oid_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		kp = find_kp_by_oid(buf, oid_len);
		if (kp == NULL) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		/*
		 * RFC5280 sect 4.2.1.12 contains "Conforming CAs SHOULD NOT
		 * mark this extension as critical if the anyExtendedKeyUsage
		 * KeyPurposeId is present." We enforce this expected behavior."
		 */
		if ((kp->oid == _id_kp_anyEKU) && critical) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += oid_len;
		off += oid_len;
		remain -= oid_len;
	}

	ctx->has_eku = 1;

	ret = 0;

out:
	return ret;
}

/*
 *  ReasonFlags ::= BIT STRING {
 *       unused                  (0),
 *       keyCompromise           (1),
 *       cACompromise            (2),
 *       affiliationChanged      (3),
 *       superseded              (4),
 *       cessationOfOperation    (5),
 *       certificateHold         (6),
 *       privilegeWithdrawn      (7),
 *       aACompromise            (8) }
 *
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten;
  @*/
static int parse_crldp_reasons(const u8 *buf, u32 len, u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0;
	u16 val = 0;
	int ret;

	if ((buf == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_id_len(buf, len, CLASS_CONTEXT_SPECIFIC, 1,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	len -= hdr_len;

	ret = parse_nine_bit_named_bit_list(buf, data_len, &val);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/*
 *     DistributionPoint ::= SEQUENCE {
 *          distributionPoint       [0]     DistributionPointName OPTIONAL,
 *          reasons                 [1]     ReasonFlags OPTIONAL,
 *          cRLIssuer               [2]     GeneralNames OPTIONAL }
 *
 *     DistributionPointName ::= CHOICE {
 *          fullName                [0]     GeneralNames,
 *          nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
 *
 *     ReasonFlags ::= BIT STRING {
 *          unused                  (0),
 *          keyCompromise           (1),
 *          cACompromise            (2),
 *          affiliationChanged      (3),
 *          superseded              (4),
 *          cessationOfOperation    (5),
 *          certificateHold         (6),
 *          privilegeWithdrawn      (7),
 *          aACompromise            (8) }
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(eaten, ctx, buf+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (0 < *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    ctx->one_crldp_has_all_reasons;
  @*/
static int parse_DistributionPoint(cert_parsing_ctx *ctx,
				   const u8 *buf, u32 len, u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0, remain = 0, total_len = 0;
	int dp_or_issuer_present = 0;
	u32 parsed = 0;
	int ret, has_all_reasons = 0;

	if ((buf == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* DistributionPoint is a sequence */
	ret = parse_id_len(buf, len,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ret = -__LINE__;
		goto out;
	}

	total_len = hdr_len + data_len;
	/*@ assert total_len > 0; */
	remain = data_len;
	buf += hdr_len;

	/*
	 * Check if we have a (optional) distributionPoint field
	 * (of type DistributionPointName)
	 */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 0,
			   &hdr_len, &data_len);
	if (!ret) {
		u32 dpn_remain = 0, dpn_eaten = 0;
		u8 dpn_type;

		buf += hdr_len;
		remain -= hdr_len;
		dpn_remain = data_len;

		if (data_len == 0) {
			ret = -__LINE__;
			goto out;
		}

		dpn_type = buf[0];

		/*
		 * distributionPoint field of type DistributionPointName
		 * can be either a fullName or a nameRelativeToCRLIssuer.
		 */
		switch (dpn_type) {
		case 0xa0: /* fullName (i.e. a GeneralNames) */
			ret = parse_GeneralNames(buf, dpn_remain,
						 CLASS_CONTEXT_SPECIFIC, 0,
						 &dpn_eaten);
			if (ret) {
				ERROR_TRACE_APPEND(__LINE__);
				goto out;
			}

			dpn_remain -= dpn_eaten;
			buf += dpn_eaten;
			break;

		case 0xa1: /* nameRelativeToCRLIssuer (RDN) */
			/*
			 * This form of distributionPoint is never used
			 * in practice in real X.509 certs, so not
			 * supported here. Note that RFC5280 has the
			 * following: "Conforming CAs SHOULD NOT use
			 * nameRelativeToCRLIssuer to specify distribution
			 * point names."
			 */
			ret = -__LINE__;
			goto out;
			break;

		default:
			ret = -__LINE__;
			goto out;
			break;
		}

		if (dpn_remain) {
			ret = -__LINE__;
			goto out;
		}

		/* Record the fact we found a DP */
		dp_or_issuer_present |= 1;

		remain -= data_len;
	}

	/* Check if we have a (optional) ReasonFlags */
	ret = parse_id_len(buf, remain, CLASS_CONTEXT_SPECIFIC, 1,
			   &hdr_len, &data_len);
	if (!ret) {
		ret = parse_crldp_reasons(buf, remain, &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += parsed;
		remain -= parsed;
	} else {
		/*
		 * RFC 5280 has "If the DistributionPoint omits the reasons
		 * field, the CRL MUST include revocation information for all
		 * reasons", i.e. no reasonFlags means all reasons.
		 */
		has_all_reasons = 1;
	}

	/* Check if we have a (optional) cRLIssuer (GeneralNames) */
	ret = parse_GeneralNames(buf, remain, CLASS_CONTEXT_SPECIFIC, 2,
				 &parsed);
	if (!ret) {
		/* Record the fact we found a cRLIssuer */
		dp_or_issuer_present |= 1;

		buf += parsed;
		remain -= parsed;
	}

	if (remain) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * RFC580 has (about DP and cRLIssuer): "While each of these fields is
	 * optional, a DistributionPoint MUST NOT consist of only the reasons
	 * field; either distributionPoint or cRLIssuer MUST be present."
	 */
	if (!dp_or_issuer_present) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = total_len;
	ctx->one_crldp_has_all_reasons |= has_all_reasons;
	/*@ assert *eaten > 0; */

	ret = 0;

out:
	return ret;
}


/*
 * 4.2.1.13. CRL Distribution Points
 * 4.2.1.15. Freshet CRL (a.k.a Delta CRL Distribution Point)
 *
 *     CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
 *
 * Note that the Freshest CRL extension uses the exact same syntax and
 * convention as CRLDP extension. The only minor difference is that section
 * 4.2.1.13 has that "The extension SHOULD be non-critical" and section
 * 4.2.1.15 has that "The extension MUST be marked as non-critical by
 * conforming CAs". We handle that by requiring that both extensions
 * be marked as non-critical.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns ctx->has_crldp,
	    ctx->one_crldp_has_all_reasons;
  @*/
static int parse_ext_CRLDP(cert_parsing_ctx *ctx,
			   const u8 *cert, u32 off, u32 len,
			   int critical)
{
	u32 hdr_len = 0, data_len = 0, remain;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* See comment above */
	if (critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, len,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	remain = data_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->has_crldp = 1;
	ctx->one_crldp_has_all_reasons = 0;

	/* Iterate on DistributionPoint */
	/*@
	  @ loop assigns ret, buf, remain, ctx->one_crldp_has_all_reasons;
	  @ loop invariant \valid_read(buf + (0 .. (remain - 1)));
	  @ loop variant remain;
	  @ */
	while (remain) {
		u32 eaten = 0;

		ret = parse_DistributionPoint(ctx, buf, remain, &eaten);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= eaten;
		buf += eaten;
	}

	ret = 0;

out:
	return ret;
}

/*
 * 4.2.1.14. Inhibit anyPolicy
 *
 * InhibitAnyPolicy ::= SkipCerts
 *
 * SkipCerts ::= INTEGER (0..MAX)
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
#define MAX_INHIBITANYPOLICY 64
static int parse_ext_inhibitAnyPolicy(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
				      const u8 *cert, u32 off, u32 len,
				      int critical)
{
	const u8 *buf = cert + off;
	u32 eaten = 0, hdr_len = 0, data_len = 0;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * 4.2.1.14 of RFC5280 has "Conforming CAs MUST mark this
	 * extension as critical".
	 */
	if (!critical) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_integer(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
			    &hdr_len, &data_len);
	if (ret) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	eaten = hdr_len + data_len;

	/*
	 * We limit SkipCerts values to integers between 0 and
	 * MAX_INHIBITANYPOLICY. This implies an encoding on 3 bytes.
	 */
	if (eaten != 3) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if ((buf[2] & 0x80) || (buf[2] > MAX_INHIBITANYPOLICY)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (eaten != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/* The OID we will support in final implementation */
static const u8 _ext_oid_AIA[] =               { 0x06, 0x08, 0x2b, 0x06, 0x01,
						 0x05, 0x05, 0x07, 0x01, 0x01 };
static const u8 _ext_oid_subjectDirAttr[] =    { 0x06, 0x03, 0x55, 0x1d, 0x09 };
static const u8 _ext_oid_SKI[] =               { 0x06, 0x03, 0x55, 0x1d, 0x0e };
static const u8 _ext_oid_keyUsage[] =          { 0x06, 0x03, 0x55, 0x1d, 0x0f };
static const u8 _ext_oid_SAN[] =               { 0x06, 0x03, 0x55, 0x1d, 0x11 };
static const u8 _ext_oid_IAN[] =               { 0x06, 0x03, 0x55, 0x1d, 0x12 };
static const u8 _ext_oid_basicConstraints[] =  { 0x06, 0x03, 0x55, 0x1d, 0x13 };
static const u8 _ext_oid_nameConstraints[] =   { 0x06, 0x03, 0x55, 0x1d, 0x1e };
static const u8 _ext_oid_CRLDP[] =             { 0x06, 0x03, 0x55, 0x1d, 0x1f };
static const u8 _ext_oid_certPolicies[] =      { 0x06, 0x03, 0x55, 0x1d, 0x20 };
static const u8 _ext_oid_policyMapping[] =     { 0x06, 0x03, 0x55, 0x1d, 0x21 };
static const u8 _ext_oid_AKI[] =               { 0x06, 0x03, 0x55, 0x1d, 0x23 };
static const u8 _ext_oid_policyConstraints[] = { 0x06, 0x03, 0x55, 0x1d, 0x24 };
static const u8 _ext_oid_EKU[] =               { 0x06, 0x03, 0x55, 0x1d, 0x25 };
static const u8 _ext_oid_FreshestCRL[] =       { 0x06, 0x03, 0x55, 0x1d, 0x2e };
static const u8 _ext_oid_inhibitAnyPolicy[] =  { 0x06, 0x03, 0x55, 0x1d, 0x36 };

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @
  @ assigns \nothing;
  @*/
static int parse_ext_bad_oid(cert_parsing_ctx ATTRIBUTE_UNUSED *ctx,
			     const u8 *cert, u32 ATTRIBUTE_UNUSED off, u32 len,
			     int ATTRIBUTE_UNUSED critical)
{
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

#ifdef TEMPORARY_LAXIST_HANDLE_COMMON_UNSUPPORTED_EXT_OIDS
/*
 * Some common OID for which we DO NOT CURRENTLY support data parsing but may
 * include for tests only to progress in certificates and improve code coverage
 */
static const u8 _ext_oid_bad_ct1[] = {
	0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
	0x01, 0x01
};
static const u8 _ext_oid_bad_ct_poison[] = {
	0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6,
	0x79, 0x02, 0x04, 0x03
};
static const u8 _ext_oid_bad_ct_enabled[] = {
	0x06, 0x0a, 0x2b, 0x06,	 0x01, 0x04, 0x01, 0xd6,
	0x79, 0x02, 0x04, 0x02
};
static const u8 _ext_oid_bad_ns_cert_type[] = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8,
	0x42, 0x01, 0x01
};
static const u8 _ext_oid_bad_szOID_ENROLL[] = {
	0x06, 0x09, 0x2b, 0x06,  0x01, 0x04, 0x01, 0x82,
	0x37, 0x14, 0x02
};
static const u8 _ext_oid_bad_smime_cap[] = {
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x09, 0x0f
};
static const u8 _ext_oid_bad_ns_comment[] = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8,
	0x42, 0x01, 0x0d
};
static const u8 _ext_oid_bad_deprecated_AKI[] = {
	0x06, 0x03, 0x55, 0x1d, 0x01
};
static const u8 _ext_oid_bad_szOID_CERT_TEMPLATE[] = {
	0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
	0x37, 0x15, 0x07
};
static const u8 _ext_oid_bad_pkixFixes[] = {
	0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97,
	0x55, 0x03, 0x01, 0x05
};
static const u8 _ext_oid_bad_ns_ca_policy_url[] = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8,
	0x42, 0x01, 0x08
};
static const u8 _ext_oid_bad_szOID_CERTSRV_CA_VERS[] = {
	0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
	0x37, 0x15, 0x01
};
static const u8 _ext_oid_bad_szOID_APP_CERT_POL[] = {
	0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
	0x37, 0x15, 0x0a
};
static const u8 _ext_oid_bad_priv_key_usage_period[] = {
	0x06, 0x03, 0x55, 0x1d, 0x10
};
static const u8 _ext_oid_bad_subject_signing_tool[] = {
	0x06, 0x05, 0x2a, 0x85,	0x03, 0x64, 0x6f
};
static const u8 _ext_oid_bad_issuer_signing_tool[] = {
	0x06, 0x05, 0x2a, 0x85,	0x03, 0x64, 0x70
};
static const u8 _ext_oid_bad_szOID_CERTSRV_PREVIOUS_CERT_HASH[] = {
	0x06, 0x09, 0x2b, 0x06,	0x01, 0x04, 0x01,
	0x82, 0x37, 0x15, 0x02
};
#endif

typedef struct {
	const u8 *oid;
	u32 oid_len;
	int (*parse_ext_params)(cert_parsing_ctx *ctx,
				const u8 *cert, u32 off, u32 len, int critical);
} _ext_oid;

static const _ext_oid generic_unsupported_ext_oid = {
	.oid = NULL,
	.oid_len = 0,
	.parse_ext_params = parse_ext_bad_oid
};

static const _ext_oid known_ext_oids[] = {
	{ .oid = _ext_oid_AIA,
	  .oid_len = sizeof(_ext_oid_AIA),
	  .parse_ext_params = parse_ext_AIA,
	},
	{ .oid = _ext_oid_AKI,
	  .oid_len = sizeof(_ext_oid_AKI),
	  .parse_ext_params = parse_ext_AKI,
	},
	{ .oid = _ext_oid_SKI,
	  .oid_len = sizeof(_ext_oid_SKI),
	  .parse_ext_params = parse_ext_SKI,
	},
	{ .oid = _ext_oid_keyUsage,
	  .oid_len = sizeof(_ext_oid_keyUsage),
	  .parse_ext_params = parse_ext_keyUsage,
	},
	{ .oid = _ext_oid_certPolicies,
	  .oid_len = sizeof(_ext_oid_certPolicies),
	  .parse_ext_params = parse_ext_certPolicies,
	},
	{ .oid = _ext_oid_policyMapping,
	  .oid_len = sizeof(_ext_oid_policyMapping),
	  .parse_ext_params = parse_ext_policyMapping,
	},
	{ .oid = _ext_oid_SAN,
	  .oid_len = sizeof(_ext_oid_SAN),
	  .parse_ext_params = parse_ext_SAN,
	},
	{ .oid = _ext_oid_IAN,
	  .oid_len = sizeof(_ext_oid_IAN),
	  .parse_ext_params = parse_ext_IAN,
	},
	{ .oid = _ext_oid_subjectDirAttr,
	  .oid_len = sizeof(_ext_oid_subjectDirAttr),
	  .parse_ext_params = parse_ext_subjectDirAttr,
	},
	{ .oid = _ext_oid_basicConstraints,
	  .oid_len = sizeof(_ext_oid_basicConstraints),
	  .parse_ext_params = parse_ext_basicConstraints,
	},
	{ .oid = _ext_oid_nameConstraints,
	  .oid_len = sizeof(_ext_oid_nameConstraints),
	  .parse_ext_params = parse_ext_nameConstraints,
	},
	{ .oid = _ext_oid_policyConstraints,
	  .oid_len = sizeof(_ext_oid_policyConstraints),
	  .parse_ext_params = parse_ext_policyConstraints,
	},
	{ .oid = _ext_oid_EKU,
	  .oid_len = sizeof(_ext_oid_EKU),
	  .parse_ext_params = parse_ext_EKU,
	},
	{ .oid = _ext_oid_CRLDP,
	  .oid_len = sizeof(_ext_oid_CRLDP),
	  .parse_ext_params = parse_ext_CRLDP,
	},
	{ .oid = _ext_oid_inhibitAnyPolicy,
	  .oid_len = sizeof(_ext_oid_inhibitAnyPolicy),
	  .parse_ext_params = parse_ext_inhibitAnyPolicy,
	},
	{ .oid = _ext_oid_FreshestCRL,
	  .oid_len = sizeof(_ext_oid_FreshestCRL),
	  .parse_ext_params = parse_ext_CRLDP,
	},
#ifdef TEMPORARY_LAXIST_HANDLE_COMMON_UNSUPPORTED_EXT_OIDS
	{ .oid = _ext_oid_bad_ct1,
	  .oid_len = sizeof(_ext_oid_bad_ct1),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_ct_poison,
	  .oid_len = sizeof(_ext_oid_bad_ct_poison),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_ct_enabled,
	  .oid_len = sizeof(_ext_oid_bad_ct_enabled),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_ns_cert_type,
	  .oid_len = sizeof(_ext_oid_bad_ns_cert_type),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_szOID_ENROLL,
	  .oid_len = sizeof(_ext_oid_bad_szOID_ENROLL),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_smime_cap,
	  .oid_len = sizeof(_ext_oid_bad_smime_cap),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_ns_comment,
	  .oid_len = sizeof(_ext_oid_bad_ns_comment),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_deprecated_AKI,
	  .oid_len = sizeof(_ext_oid_bad_deprecated_AKI),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_szOID_CERT_TEMPLATE,
	  .oid_len = sizeof(_ext_oid_bad_szOID_CERT_TEMPLATE),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_pkixFixes,
	  .oid_len = sizeof(_ext_oid_bad_pkixFixes),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_ns_ca_policy_url,
	  .oid_len = sizeof(_ext_oid_bad_ns_ca_policy_url),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_szOID_CERTSRV_CA_VERS,
	  .oid_len = sizeof(_ext_oid_bad_szOID_CERTSRV_CA_VERS),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_szOID_APP_CERT_POL,
	  .oid_len = sizeof(_ext_oid_bad_szOID_APP_CERT_POL),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_priv_key_usage_period,
	  .oid_len = sizeof(_ext_oid_bad_priv_key_usage_period),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_subject_signing_tool,
	  .oid_len = sizeof(_ext_oid_bad_subject_signing_tool),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_issuer_signing_tool,
	  .oid_len = sizeof(_ext_oid_bad_issuer_signing_tool),
	  .parse_ext_params = parse_ext_bad_oid,
	},
	{ .oid = _ext_oid_bad_szOID_CERTSRV_PREVIOUS_CERT_HASH,
	  .oid_len = sizeof(_ext_oid_bad_szOID_CERTSRV_PREVIOUS_CERT_HASH),
	  .parse_ext_params = parse_ext_bad_oid,
	},
#endif
};

#define NUM_KNOWN_EXT_OIDS (sizeof(known_ext_oids) / sizeof(known_ext_oids[0]))

/*
 * We limit the amount of extensions we accept per certificate. This can be
 * done because each kind of extension is allowed to appear only once in a
 * given certificate. Note that it is logical to allow
 */
#define MAX_EXT_NUM_PER_CERT NUM_KNOWN_EXT_OIDS

/*@
  @ requires ((len > 0) && (buf != NULL)) ==> \valid_read(buf + (0 .. (len - 1)));
  @
  @ ensures (\result != NULL) ==> \exists integer i ; 0 <= i < NUM_KNOWN_EXT_OIDS && \result == &known_ext_oids[i];
  @ ensures (len == 0) ==> \result == NULL;
  @ ensures (buf == NULL) ==> \result == NULL;
  @
  @ assigns \nothing;
  @*/
static _ext_oid const * find_ext_by_oid(const u8 *buf, u32 len)
{
	const _ext_oid *found = NULL;
	const _ext_oid *cur = NULL;
	u16 k;

	if ((buf == NULL) || (len == 0)) {
		goto out;
	}

	/*@ loop unroll NUM_KNOWN_EXT_OIDS ;
	  @ loop invariant 0 <= k <= NUM_KNOWN_EXT_OIDS;
	  @ loop invariant found == NULL;
	  @ loop assigns cur, found, k;
	  @ loop variant (NUM_KNOWN_EXT_OIDS - k);
	  @*/
	for (k = 0; k < NUM_KNOWN_EXT_OIDS; k++) {
		int ret;

		cur = &known_ext_oids[k];

		/*@ assert cur == &known_ext_oids[k];*/
		if (cur->oid_len != len) {
			continue;
		}

		/*@ assert \valid_read(buf + (0 .. (len - 1))); @*/
		ret = !bufs_differ(cur->oid, buf, cur->oid_len);
		if (ret) {
			found = cur;
			break;
		}
	}

out:
	return found;
}

/*@
  @ requires ext != \null;
  @ requires \valid(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1)));
  @ requires \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1)));
  @ requires \separated(ext, parsed_oid_list);
  @
  @ ensures \result <= 0;
  @
  @ assigns parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)];
  @*/
static int check_record_ext_unknown(const _ext_oid *ext,
				    const _ext_oid **parsed_oid_list)
{
	u16 pos = 0;
	int ret;

	/*@
	  @ loop invariant pos <= MAX_EXT_NUM_PER_CERT;
	  @ loop assigns ret, pos, parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)];
	  @ loop variant MAX_EXT_NUM_PER_CERT - pos;
	  @*/
	while (pos < MAX_EXT_NUM_PER_CERT) {
		/*
		 * Check if we are at the end of already seen extensions. In
		 * that case, record the extension as a new one.
		 */
		if (parsed_oid_list[pos] == NULL) {
			parsed_oid_list[pos] = ext;
			break;
		}

		if (ext == parsed_oid_list[pos]) {
			ret = -__LINE__;
			goto out;
		}

		pos += 1;
	}

	/*
	 * If we went to the end of our array, this means there are too many
	 * extensions in the certificate.
	 */
	if (pos >= MAX_EXT_NUM_PER_CERT) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * Parse one extension.
 *
 *  Extension  ::=  SEQUENCE  {
 *       extnID      OBJECT IDENTIFIER,
 *       critical    BOOLEAN DEFAULT FALSE,
 *       extnValue   OCTET STRING
 *                   -- contains the DER encoding of an ASN.1 value
 *                   -- corresponding to the extension type identified
 *                   -- by extnID
 *       }
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \valid(parsed_oid_list);
  @ requires \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1)));
  @ requires \separated(ctx, cert+(..),parsed_oid_list,eaten);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 <= *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)], *eaten, *ctx;
  @*/
static int parse_x509_Extension(cert_parsing_ctx *ctx,
				const u8 *cert, u32 off, u32 len,
				const _ext_oid **parsed_oid_list,
				u32 *eaten)
{
	u32 data_len = 0, hdr_len = 0, remain = 0;
	u32 ext_hdr_len = 0, ext_data_len = 0, oid_len = 0;
	u32 saved_ext_len = 0, parsed = 0;
	const u8 *buf = cert + off;
	const _ext_oid *ext = NULL;
	int critical = 0;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

	remain = len;

	/* Check we are dealing with a valid sequence */
	ret = parse_id_len(buf, remain,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &ext_hdr_len, &ext_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += ext_hdr_len;
	off += ext_hdr_len;
	remain -= ext_hdr_len;
	saved_ext_len = ext_hdr_len + ext_data_len;

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

	/*
	 * Let's parse the OID and then check if we have
	 * an associated handler for that extension.
	 */
	ret = parse_OID(buf, ext_data_len, &oid_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

	ext = find_ext_by_oid(buf, oid_len);
	if (ext == NULL) {
#ifndef TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_EXT_OIDS
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
#else
		ext = &generic_unsupported_ext_oid;
#endif
	}

	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

	/*
	 * There is no efficient way to support check of duplicate OID for
	 * extension we do not known, i.e. if
	 * TEMPORARY_LAXIST_HANDLE_ALL_REMAINING_EXT_OIDS has been enabled
	 * _and_ we end up on an unsupported OID, we just skip duplicate
	 * check, as documented.
	 */
	if (ext != &generic_unsupported_ext_oid) {
		/*
		 * Now that we know the OID is one we support, we verify
		 * this is the first time we handle an instance of this
		 * type. Having multiple instances of a given extension
		 * in a certificate is forbidden by both section 4.2 of
		 * RFC5280 and section 8 of X.509, w/ respectively
		 *
		 * - "A certificate MUST NOT include more than one
		 *    instance of a particular extension."
		 * - "For all certificate extensions, CRL extensions,
		 *    and CRL entry extensions defined in this Directory
		 *    Specification, there shall be no more than one
		 *    instance of each extension type in any certificate,
		 *    CRL, or CRL entry, respectively."
		 *
		 * This is done by recording for each extension we
		 * processed the pointer to its vtable and compare
		 * it with current one.
		 */
		ret = check_record_ext_unknown(ext, parsed_oid_list);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	buf += oid_len;
	off += oid_len;
	ext_data_len -= oid_len;

	/*
	 * Now that we got the OID, let's check critical
	 * field value if present. It's a boolean
	 * defaulting to FALSE (in which case, it is absent).
	 * We could parse it as an integer but that
	 * would be a lot of work for three simple bytes.
	 */
	ret = parse_boolean(buf, ext_data_len, &parsed);
	if (ret) {
		/*
		 * parse_boolean() returned an error which means this
		 * was either a boolean with invalid content or
		 * something else. If this was indeed a boolean, we can
		 * just leave. Otherwise, this just measn the critical
		 * flag was missing and the default value (false) applies,
		 * in which case, we can continue parsing.
		 */
		if (ext_data_len && (buf[0] == ASN1_TYPE_BOOLEAN)) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	} else {
		/*
		 * We now know it's a valid BOOLEAN, *but* in our
		 * case (DER), the DEFAULT FALSE means we cannot
		 * accept an encoded value of FALSE. Note that we
		 * sanity check the value we expect for the length
		 */
		if (parsed != 3) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

#ifndef TEMPORARY_LAXIST_EXTENSION_CRITICAL_FLAG_BOOLEAN_EXPLICIT_FALSE
		if (buf[2] == 0x00) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
#endif

		/*
		 * We now know the BOOLEAN is present and has
		 * a value of TRUE. Record that.
		 */
		critical = 1;

		buf += parsed;
		off += parsed;
		ext_data_len -= parsed;
	}

	/*
	 * We should now be in front of the octet string
	 * containing the extnValue.
	 */
	ret = parse_id_len(buf, ext_data_len,
			   CLASS_UNIVERSAL, ASN1_TYPE_OCTET_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;
	ext_data_len -= hdr_len;

	/* Check nothing remains behind the extnValue */
	if (data_len != ext_data_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Parse the parameters for that extension */
	/*@ assert ext->parse_ext_params \in {
		  parse_ext_AIA, parse_ext_AKI,
		  parse_ext_SKI, parse_ext_keyUsage,
		  parse_ext_certPolicies, parse_ext_policyMapping,
		  parse_ext_SAN, parse_ext_IAN, parse_ext_subjectDirAttr,
		  parse_ext_basicConstraints, parse_ext_nameConstraints,
		  parse_ext_policyConstraints, parse_ext_EKU,
		  parse_ext_CRLDP, parse_ext_inhibitAnyPolicy,
		  parse_ext_bad_oid }; @*/
	/*@ calls parse_ext_AIA, parse_ext_AKI,
		  parse_ext_SKI, parse_ext_keyUsage,
		  parse_ext_certPolicies, parse_ext_policyMapping,
		  parse_ext_SAN, parse_ext_IAN,
		  parse_ext_subjectDirAttr, parse_ext_basicConstraints,
		  parse_ext_nameConstraints, parse_ext_policyConstraints,
		  parse_ext_EKU, parse_ext_CRLDP,
		  parse_ext_inhibitAnyPolicy, parse_ext_bad_oid ; @*/
	ret = ext->parse_ext_params(ctx, cert, off, ext_data_len, critical);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = saved_ext_len;
	ret = 0;

out:
	return ret;
}



/*
 * Parse X.509 extensions.
 *
 *  TBSCertificate  ::=  SEQUENCE  {
 *
 *       ...
 *
 *       extensions      [3]  EXPLICIT Extensions OPTIONAL
 *  }
 *
 *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 *
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(eaten, ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (1 <= *eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_Extensions(cert_parsing_ctx *ctx,
				 const u8 *cert, u32 off, u32 len,
				 u32 *eaten)
{

	u32 data_len = 0, hdr_len = 0, remain = 0;
	const u8 *buf = cert + off;
	u32 saved_len = 0;
	const _ext_oid *parsed_oid_list[MAX_EXT_NUM_PER_CERT];
	int ret;
	u16 i;

	if ((cert == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Extensions in X.509 v3 certificates is an EXPLICITLY tagged
	 * sequence.
	 */
	ret = parse_explicit_id_len(buf, len, 3,
				    CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
				    &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain = data_len;
	buf += hdr_len;
	off += hdr_len;
	/*@ assert \valid_read(buf + (0 .. (remain - 1))); */

	saved_len = hdr_len + data_len;
	/*@ assert saved_len <= len; */
	/*@ assert data_len <= saved_len; */

	/* If present, it must contain at least one extension */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Initialize list of already seen extensions */
	/*@ loop unroll MAX_EXT_NUM_PER_CERT;
	  @ loop assigns i, parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)];
	  @ loop invariant (i < MAX_EXT_NUM_PER_CERT) ==> \valid(&parsed_oid_list[i]);
	  @ loop variant (MAX_EXT_NUM_PER_CERT - i);
	  @*/
	for (i = 0; i < MAX_EXT_NUM_PER_CERT; i++) {
		parsed_oid_list[i] = NULL;
	}
	/*@ assert \initialized(parsed_oid_list + (0 .. (MAX_EXT_NUM_PER_CERT - 1))); */

	/* Now, let's work on each extension in the sequence */
	/*@
	  @ loop assigns off, ret, buf, remain, parsed_oid_list[0 .. (MAX_EXT_NUM_PER_CERT - 1)], *ctx;
	  @ loop invariant (remain != 0) ==> \valid_read(cert + (off .. (off + remain - 1)));
	  @ loop invariant (remain != 0) ==> off + remain <= MAX_UINT32;
	  @ loop variant remain;
	  @*/
	while (remain) {
		u32 ext_len = 0;

		ret = parse_x509_Extension(ctx, cert, off, remain,
					   parsed_oid_list, &ext_len);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		remain -= ext_len;
		buf += ext_len;
		off += ext_len;
	}

	/*
	 * RFC5280 has "If the subject field contains an empty sequence,
	 * then the issuing CA MUST include a subjectAltName extension
	 * that is marked as critical."
	 */
	if (ctx->empty_subject) {
		if (!ctx->has_san) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
		if (!ctx->san_critical) {
			ret = -__LINE__;
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}
	}

	/*@ assert 1 <= saved_len <= len; */
	*eaten = saved_len;

	ret = 0;

out:
	return ret;
}

/*
 *
 *	TBSCertificate	::=  SEQUENCE  {
 *	version		[0]  EXPLICIT Version DEFAULT v1,
 *	serialNumber	     CertificateSerialNumber,
 *	signature	     AlgorithmIdentifier,
 *	issuer		     Name,
 *	validity	     Validity,
 *	subject		     Name,
 *	subjectPublicKeyInfo SubjectPublicKeyInfo,
 *	issuerUniqueID	[1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *			     -- If present, version MUST be v2 or v3
 *	subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *			     -- If present, version MUST be v2 or v3
 *	extensions	[3]  EXPLICIT Extensions OPTIONAL
 *			     -- If present, version MUST be v3
 *	}
 *
 * On success, the function returns the size of the tbsCertificate
 * structure in 'eaten' parameter. It also provides in 'sig_alg'
 * a pointer to the signature algorithm found in the signature field.
 * This one is provided to be able to check later against the signature
 * algorithm found in the signatureAlgorithm field of the certificate.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(sig_alg, eaten, cert+(..), ctx);
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (sig_alg == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> (1 < *eaten <= len);
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_start));
  @ ensures (\result == 0) ==> \initialized(&(ctx->tbs_sig_alg_len));
  @ ensures (\result == 0) ==> \initialized(&(ctx->sig_alg));
  @ ensures (\result == 0) ==> ctx->tbs_sig_alg_start < off + *eaten;
  @
  @ assigns *eaten, *ctx, *sig_alg;
  @*/
static int parse_x509_tbsCertificate(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len,
				     const _sig_alg **sig_alg, u32 *eaten)
{
	u32 tbs_data_len = 0;
	u32 tbs_hdr_len = 0;
	u32 tbs_cert_len = 0;
	u32 remain = 0;
	u32 parsed = 0;
	u32 cur_off = off;
	const u8 *buf = cert + cur_off;
	const u8 *subject_ptr, *issuer_ptr;
	u32 subject_len, issuer_len;
	const _sig_alg *alg = NULL;
	int ret, empty_issuer = 1;

	if ((ctx == NULL) || (cert == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	/*
	 * Let's first check we are dealing with a valid sequence containing
	 * all the elements of the certificate.
	 */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &tbs_hdr_len, &tbs_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	tbs_cert_len = tbs_hdr_len + tbs_data_len;
	buf += tbs_hdr_len;
	cur_off += tbs_hdr_len;
	remain = tbs_data_len;

	/*
	 * Now, we can start and parse all the elements in the sequence
	 * one by one.
	 */

	/* version */
	ret = parse_x509_Version(ctx, cert, cur_off, remain, &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/* serialNumber */
	ret = parse_CertSerialNumber(ctx, cert, cur_off, remain,
				     CLASS_UNIVERSAL, ASN1_TYPE_INTEGER,
				     &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/* signature */
	ret = parse_x509_tbsCert_sig_AlgorithmIdentifier(ctx, cert, cur_off, remain,
							 &alg, &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert \initialized(&(ctx->tbs_sig_alg_start)); */
	/*@ assert ctx->tbs_sig_alg_start == cur_off; */
	/*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */
	/*@ assert \initialized(&(ctx->tbs_sig_alg_len)); */
	/*@ assert \initialized(&(ctx->sig_alg)); */

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/* issuer */
	ret = parse_x509_Name(buf, remain, &parsed, &empty_issuer);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	ctx->issuer_start = cur_off;
	ctx->issuer_len = parsed;

	/*
	 * As described in section 4.1.2.4 of RFC 5280, "The issuer field MUST
	 * contain a non-empty distinguished name (DN)".
	 */
	/*@ assert (empty_issuer == 0) || (empty_issuer == 1); */
	if (empty_issuer) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	issuer_ptr = buf;
	issuer_len = parsed;

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/* validity */
	ret = parse_x509_Validity(ctx, cert, cur_off, remain, &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/* subject */
	ret = parse_x509_Name(buf, remain, &parsed, &ctx->empty_subject);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->subject_start = cur_off;
	ctx->subject_len = parsed;

	subject_ptr = buf;
	subject_len = parsed;

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/* We can now check if subject and issuer fields are identical */
	ctx->subject_issuer_identical = 0;
	if (subject_len == issuer_len) {
		ctx->subject_issuer_identical = !bufs_differ(subject_ptr,
							     issuer_ptr,
							     issuer_len);
	}

	/* subjectPublicKeyInfo */
	ret = parse_x509_subjectPublicKeyInfo(ctx, cert, cur_off, remain, &parsed);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */

	buf += parsed;
	cur_off += parsed;
	remain -= parsed;

	/*
	 * At that point, the remainder of the tbsCertificate part
	 * is made of 3 *optional* elements:
	 *
	 *     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	 *     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	 *     extensions      [3]  EXPLICIT Extensions OPTIONAL
	 *
	 *  w/ UniqueIdentifier  ::=  BIT STRING
	 *     Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	 *
	 * Section 4.1.2.8 of RFC 5280 explicitly states that "CAs
	 * conforming to this profile MUST NOT generate certificates
	 * with unique identifier" but "Applications conforming to
	 * this profile SHOULD be capable of parsing certificates
	 * that include unique identifiers, but there are no processing
	 * requirements associated with the unique identifiers."
	 *
	 * Additionnally, some tests performed on 9826768 (of 18822321)
	 * certificates that validate in a 2011 TLS campaign, we do not
	 * have any certificate w/ either a subjectUniqueID or
	 * issuerUniqueID.
	 *
	 * For that reason, in order to simplify parsing, we expect NOT
	 * to find either a subject or issuer unique identifier and to
	 * directly find extensions, if any. This is done by checking if
	 * data remain at that point. If that is the case, we perform
	 * a full parsing of the Extensions.
	 */
	if (remain) {
		ret = parse_x509_Extensions(ctx, cert, cur_off, remain, &parsed);
		if (ret) {
			ERROR_TRACE_APPEND(__LINE__);
			goto out;
		}

		buf += parsed;
		cur_off += parsed;
		remain -= parsed;
	}

	/*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */

	if (remain != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * RFC 5280 requires that SKI extension "MUST appear in all conforming
	 * CA certificates, that is, all certificates including the basic
	 * constraints extension (Section 4.2.1.9) where the value of cA is
	 * TRUE"
	 */
#ifndef TEMPORARY_LAXIST_CA_WO_SKI
	if (ctx->ca_true && !ctx->has_ski) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
#endif

	/*
	 * RFC 5280 has "If the keyCertSign bit is asserted, then the cA bit in
	 * the basic constraints extension (Section 4.2.1.9) MUST also be
	 * asserted.
	 *
	 * It also has the following regarding basicConstraints extension:
	 * "Conforming CAs MUST include this extension in all CA certificates
	 * that contain public keys used to validate digital signatures on
	 * certificates and MUST mark the extension as critical in such
	 * certificates."
	 *
	 * Note that we do not enforce basicConstraints criticality otherwise
	 * as required by "This extension MAY appear as a critical or
	 * non-critical extension in CA certificates that contain public keys
	 * used exclusively for purposes other than validating digital
	 * signatures on certificates. This extension MAY appear as a critical
	 * or non-critical extension in end entity certificates."
	 */
	if (ctx->keyCertSign_set && (!ctx->ca_true || !ctx->bc_critical)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * If the subject is a CRL issuer (e.g., the key usage extension, as
	 * discussed in Section 4.2.1.3, is present and the value of cRLSign is
	 * TRUE), then the subject field MUST be populated with a non-empty
	 * distinguished name matching the contents of the issuer field (Section
	 * 5.1.2.3) in all CRLs issued by the subject CRL issuer.
	 */
	if (ctx->cRLSign_set && ctx->empty_subject) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * RFC5280 has "CAs MUST NOT include the pathLenConstraint field
	 * unless the cA boolean is asserted and the key usage extension
	 * asserts the keyCertSign bit."
	 */
	if (ctx->pathLenConstraint_set &&
	    (!ctx->ca_true || !ctx->keyCertSign_set)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

       /*
	* RFC5280 has "The name constraints extension, which MUST be used only
	* in a CA certificate, ..."
	*/
	if (ctx->has_name_constraints && !ctx->ca_true) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

       /*
	* RFC5280 has "When a conforming CA includes a cRLDistributionPoints
	* extension in a certificate, it MUST include at least one
	* DistributionPoint that points to a CRL that covers the certificate
	* for all reasons."
	*/
	if (ctx->ca_true && ctx->has_crldp && !ctx->one_crldp_has_all_reasons) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert ctx->tbs_sig_alg_start < off + tbs_cert_len; */
	/*@ assert 1 < tbs_cert_len <= len; */
	*eaten = tbs_cert_len;
	/*@ assert ctx->tbs_sig_alg_start < off + *eaten; */
	*sig_alg = alg;

	ret = 0;

out:
	return ret;
}

/*
 * The function is used to parse signatureAlgorithm field found after the
 * tbsCertificate and before the signature. As the field is expected
 * to exactly match the tbsCertificate.signature field which has already
 * been fully parsed and validated, we only verify here that the element
 * to parse is identical to previously parsed tbsCertificate.signature
 * using the pointers in the context.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (0 .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \initialized(&(ctx->tbs_sig_alg_start));
  @ requires \initialized(&(ctx->tbs_sig_alg_len));
  @ requires ctx->tbs_sig_alg_start <= off;
  @ requires \separated(eaten, cert+(..), ctx);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    ctx->sig_alg_start,
	    ctx->sig_alg_len;
  @*/
static int parse_x509_signatureAlgorithm(cert_parsing_ctx *ctx,
					 const u8 *cert, u32 off, u32 len,
					 u32 *eaten)
{
	u32 prev_len;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	prev_len = ctx->tbs_sig_alg_len;
	if (prev_len > len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = bufs_differ(cert + ctx->tbs_sig_alg_start, cert + off, prev_len);
	if (ret) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	ctx->sig_alg_start = off;
	ctx->sig_alg_len = prev_len;

	*eaten = prev_len;

	ret = 0;

out:
	return ret;
}


/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->monkeysphere.sig_raw_off,
	    params->monkeysphere.sig_raw_len;
  @*/
static int parse_sig_monkey(sig_params *params,
			    const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 remain, hdr_len = 0, data_len = 0;
	const u8 *buf = cert  + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (len == 0)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	off += 1;
	remain = data_len - 1;

	/*
	 * In practice, the sig contains an ASCII string: 'use OpenPGP' in the
	 * certificate we have. XXX Revisit later.
	 */
	params->monkeysphere.sig_raw_off = off;
	params->monkeysphere.sig_raw_len = remain;

	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/*
 * All version of GOST signature algorithms (GOST R34.10-94, -2001 and -2012)
 * do encode their signature using a bitstring. This is what this helper
 * implements.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..),r_start_off,r_len,s_start_off,s_len);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> *r_start_off <= len;
  @ ensures (\result == 0) ==> *s_start_off <= len;
  @ ensures (\result == 0) ==> (u64)*r_start_off + (u64)*r_len <= len;
  @ ensures (\result == 0) ==> (u64)*s_start_off + (u64)*s_len <= len;
  @
  @ assigns *eaten, *r_start_off, *r_len, *s_start_off, *s_len;
  @*/
static int sig_gost_extract_r_s(const u8 *buf, u32 len,
				u32 *r_start_off, u32 *r_len,
				u32 *s_start_off, u32 *s_len,
				u32 *eaten)
{
	u32 remain, hdr_len = 0, data_len = 0, off = 0;
	int ret;

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	off += 1;
	remain = data_len - 1;

	/*
	 * For an unknown reason, the order of signature components is
	 * reversed, i.e. s comes before r.
	 */
	*s_start_off = off;
	*s_len = remain / 2;
	*r_start_off = off + *s_len;
	*r_len = *s_len;
	*eaten = hdr_len + data_len;

	ret = 0;

out:
	return ret;
}

/* Handle GOST R34.10-94 signature parsing */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->gost_r3410_94.r_raw_off,
	    params->gost_r3410_94.r_raw_len,
	    params->gost_r3410_94.s_raw_off,
	    params->gost_r3410_94.s_raw_len;
  @*/
static int parse_sig_gost94(sig_params *params,
			    const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 r_start_off = 0, r_len = 0, s_start_off = 0, s_len = 0;
	const u8 *buf =  cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = sig_gost_extract_r_s(buf, len, &r_start_off, &r_len,
				   &s_start_off, &s_len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	params->gost_r3410_94.r_raw_off = off + r_start_off;
	params->gost_r3410_94.r_raw_len = r_len;
	params->gost_r3410_94.s_raw_off = off + s_start_off;
	params->gost_r3410_94.s_raw_len = s_len;
	ret = 0;

out:
	return ret;
}

/* Handle GOST R34.10-2001 signature parsing */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->gost_r3410_2001.r_raw_off,
	    params->gost_r3410_2001.r_raw_len,
	    params->gost_r3410_2001.s_raw_off,
	    params->gost_r3410_2001.s_raw_len;
  @*/
static int parse_sig_gost2001(sig_params *params,
			      const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 r_start_off = 0, r_len = 0, s_start_off = 0, s_len = 0;
	const u8 *buf =  cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = sig_gost_extract_r_s(buf, len, &r_start_off, &r_len,
				   &s_start_off, &s_len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	params->gost_r3410_2001.r_raw_off = off + r_start_off;
	params->gost_r3410_2001.r_raw_len = r_len;
	params->gost_r3410_2001.s_raw_off = off + s_start_off;
	params->gost_r3410_2001.s_raw_len = s_len;
	ret = 0;

out:
	return ret;
}

/* Handle bign (Belarus Signature standard TB 34.101.45-2013) signature parsing */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->bign.sig_raw_off,
	    params->bign.sig_raw_len;
  @*/
static int parse_sig_bign(sig_params *params,
			  const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 remain, hdr_len = 0, data_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;
	off += hdr_len;

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	off += 1;
	remain = data_len - 1;

	params->bign.sig_raw_off = off;
	params->bign.sig_raw_len = remain;
	*eaten = hdr_len + data_len;
	ret = 0;

out:
	return ret;
}

/* Handle GOST R34.10-2012 signature parsing */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->gost_r3410_2012_256.r_raw_off,
	    params->gost_r3410_2012_256.r_raw_len,
	    params->gost_r3410_2012_256.s_raw_off,
	    params->gost_r3410_2012_256.s_raw_len;
  @*/
static int parse_sig_gost2012_256(sig_params *params,
				  const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 r_start_off = 0, r_len = 0, s_start_off = 0, s_len = 0;
	const u8 *buf =  cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = sig_gost_extract_r_s(buf, len, &r_start_off, &r_len,
				   &s_start_off, &s_len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	params->gost_r3410_2012_256.r_raw_off = off + r_start_off;
	params->gost_r3410_2012_256.r_raw_len = r_len;
	params->gost_r3410_2012_256.s_raw_off = off + s_start_off;
	params->gost_r3410_2012_256.s_raw_len = s_len;
	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->gost_r3410_2012_512.r_raw_off,
	    params->gost_r3410_2012_512.r_raw_len,
	    params->gost_r3410_2012_512.s_raw_off,
	    params->gost_r3410_2012_512.s_raw_len;
  @*/
static int parse_sig_gost2012_512(sig_params *params,
				  const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 r_start_off = 0, r_len = 0, s_start_off = 0, s_len = 0;
	const u8 *buf =  cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = sig_gost_extract_r_s(buf, len, &r_start_off, &r_len,
				   &s_start_off, &s_len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	params->gost_r3410_2012_512.r_raw_off = off + r_start_off;
	params->gost_r3410_2012_512.r_raw_len = r_len;
	params->gost_r3410_2012_512.s_raw_off = off + s_start_off;
	params->gost_r3410_2012_512.s_raw_len = s_len;
	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..), bs_data_start_off, bs_data_len);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> ((*bs_data_start_off + *bs_data_len) <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (bs_data_start_off == \null) ==> \result < 0;
  @ ensures (bs_data_len == \null) ==> \result < 0;
  @
  @ assigns *eaten, *bs_data_start_off, *bs_data_len;
  @*/
int parse_sig_rsa_helper(const u8 *buf, u32 len,
			 u32 *bs_data_start_off, u32 *bs_data_len,
			 u32 *eaten)
{
	u32 hdr_len = 0, data_len = 0;
	int ret;

	if ((buf == NULL) || (len == 0) || (eaten == NULL) ||
	    (bs_data_start_off == NULL) || (bs_data_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert hdr_len + data_len == len; */

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	*bs_data_start_off = hdr_len + 1;
	*bs_data_len = data_len - 1;
	*eaten = hdr_len + data_len;
	ret = 0;
	/*@ assert (*bs_data_start_off + *bs_data_len) <= len; */

out:
	return ret;
}

/*
 * RFC 8410 defines Agorithm Identifiers for Ed25519 and Ed448
 *
 * The same algorithm identifiers are used for signatures as are used
 * for public keys.  When used to identify signature algorithms, the
 * parameters MUST be absent.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), r_start_off, r_len, s_start_off, s_len);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (((u64)*r_start_off + (u64)*r_len) <= (u64)off + (u64)len);
  @ ensures (\result == 0) ==> (((u64)*s_start_off + (u64)*s_len) <= (u64)off + (u64)len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (r_start_off == \null) ==> \result < 0;
  @ ensures (r_len == \null) ==> \result < 0;
  @ ensures (s_start_off == \null) ==> \result < 0;
  @ ensures (s_len == \null) ==> \result < 0;
  @
  @ assigns *eaten, *r_start_off, *r_len, *s_start_off, *s_len;
  @*/
static int parse_sig_eddsa(const u8 *cert, u32 off, u32 len, u32 exp_sig_len,
			   u32 *r_start_off, u32 *r_len, u32 *s_start_off, u32 *s_len,
			   u32 *eaten)
{
	u32 comp_len, sig_len = 0, hdr_len = 0, data_len = 0, remain = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((cert == NULL) || (len == 0) || (eaten == NULL) ||
	    (r_start_off == NULL) || (r_len == NULL) ||
	    (s_start_off == NULL) || (s_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	buf += hdr_len;

	if (len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert hdr_len + data_len == len; */

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	sig_len = data_len - 1;
	if (sig_len != exp_sig_len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	comp_len = sig_len / 2;

	if (sig_len != (comp_len * 2)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	/*@ assert sig_len == 2 * comp_len; */

	*r_start_off = off + hdr_len + 1;
	*r_len = comp_len;
	/*@ assert *r_len == comp_len; */
	/*@ assert (u64)*r_start_off + (u64)*r_len <= (u64)off + (u64)len; */

	*s_start_off = off + hdr_len + 1 + comp_len;
	*s_len = comp_len;
	/*@ assert *s_len == comp_len; */
	/*@ assert ((u64)*s_start_off + (u64)*s_len) <= (u64)off + (u64)len; */

	/*
	 * Check there is nothing remaining in the bitstring
	 * after the two integers
	 */
	if (remain != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*eaten = hdr_len + data_len;
	ret = 0;
	/*@ assert ((u64)*r_start_off + (u64)*r_len) <= (u64)off + (u64)len; */
	/*@ assert ((u64)*s_start_off + (u64)*s_len) <= (u64)off + (u64)len; */

out:
	return ret;
}

#define ED448_SIG_LEN 114
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->ed448.r_raw_off,
	    params->ed448.r_raw_len,
	    params->ed448.s_raw_off,
	    params->ed448.s_raw_len;
  @*/
static int parse_sig_ed448(sig_params *params,
			   const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_sig_eddsa(cert, off, len, ED448_SIG_LEN,
			      &params->ed448.r_raw_off,
			      &params->ed448.r_raw_len,
			      &params->ed448.s_raw_off,
			      &params->ed448.s_raw_len,
			      eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

#define ED25519_SIG_LEN 64
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->ed25519.r_raw_off,
	    params->ed25519.r_raw_len,
	    params->ed25519.s_raw_off,
	    params->ed25519.s_raw_len;
  @*/
static int parse_sig_ed25519(sig_params *params,
			     const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_sig_eddsa(cert, off, len, ED25519_SIG_LEN,
			      &params->ed25519.r_raw_off,
			      &params->ed25519.r_raw_len,
			      &params->ed25519.s_raw_off,
			      &params->ed25519.s_raw_len,
			      eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * DSA-based signatures often share the same layout for (r,s), i.e. a bitstring
 * whose content will be parsed as a sequence of two positive integers. This
 * helper does that job by providing positions of integer *values* and length
 * along with the size of the whole structure (bitstring). Note that the
 * function cannot and does not make hypothesis on the length of r and s. This
 * checks, if needed, are left to the caller.
 */
/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..), r_start_off, r_len, s_start_off, s_len);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> ((*r_start_off + *r_len) <= len);
  @ ensures (\result == 0) ==> ((*s_start_off + *s_len) <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (r_start_off == \null) ==> \result < 0;
  @ ensures (r_len == \null) ==> \result < 0;
  @ ensures (s_start_off == \null) ==> \result < 0;
  @ ensures (s_len == \null) ==> \result < 0;
  @
  @ assigns *eaten, *r_start_off, *r_len, *s_start_off, *s_len;
  @*/
static int sig_dsa_based_extract_r_s(const u8 *buf, u32 len,
				     u32 *r_start_off, u32 *r_len,
				     u32 *s_start_off, u32 *s_len,
				     u32 *eaten)
{
	u32 bs_hdr_len = 0, bs_data_len = 0, sig_len = 0, hdr_len = 0;
	u32 data_len = 0, remain = 0, saved_sig_len = 0;
	u32 integer_len = 0;
	u32 off;
	int ret;

	if ((buf == NULL) || (len == 0) || (eaten == NULL) ||
	    (r_start_off == NULL) || (r_len == NULL) ||
	    (s_start_off == NULL) || (s_len == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_BIT_STRING,
			   &bs_hdr_len, &bs_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	saved_sig_len = bs_hdr_len + bs_data_len;
	/*@ assert saved_sig_len <= len; */
	buf += bs_hdr_len;
	off = bs_hdr_len;
	/*@ assert off + bs_data_len <= len; */

	/*
	 * We expect the bitstring data to contain at least the initial
	 * octet encoding the number of unused bits in the final
	 * subsequent octet of the bistring.
	 * */
	if (bs_data_len == 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * The signature field is always a bitstring whose content
	 * may then be interpreted depending on the signature
	 * algorithm. At the moment, we only support ECDSA signature
	 * mechanisms. In that case, the content of the bitstring
	 * is parsed as defined in RFC5480, i.e. as a sequence of
	 * two integers:
	 *
	 * ECDSA-Sig-Value ::= SEQUENCE {
	 *   r  INTEGER,
	 *   s  INTEGER
	 * }
	 *
	 * As we only structural checks here, we do not verify
	 * the values stored in the integer are valid r and s
	 * values for the specific alg/curve.
	 */

	/*
	 * We expect the initial octet to encode a value of 0
	 * indicating that there are no unused bits in the final
	 * subsequent octet of the bitstring.
	 */
	if (buf[0] != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}
	buf += 1;
	off += 1;
	sig_len = bs_data_len - 1;
	/*@ assert off + bs_data_len - 1 <= len; */
	/*@ assert off + sig_len <= len; */

	/*
	 * Now that we know we are indeed dealing w/ a DSA sig mechanism,
	 * let's check we have a sequence of two integers.
	 */
	ret = parse_id_len(buf, sig_len,
			   CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Nothing must remain in the bitstring after the sequence. */
	if (sig_len != (hdr_len + data_len)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	remain = data_len;
	buf += hdr_len;
	off += hdr_len;
	/*@ assert (off + remain) <= len; */

	/*
	 * Now, we should find the first non negative integer, r.
	 */
	ret = parse_non_negative_integer(buf, remain, CLASS_UNIVERSAL,
					 ASN1_TYPE_INTEGER,
					 &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	integer_len = hdr_len + data_len;
	/*@ assert integer_len <= remain; */
	/*@ assert (off + remain) <= len; */
	/*@ assert (off + integer_len) <= len; */
	remain -= integer_len;
	buf += integer_len;
	*r_start_off = off + hdr_len;
	/*@ assert *r_start_off == off + hdr_len; */
	*r_len = data_len;
	/*@ assert *r_len == data_len; */
	/*@ assert *r_start_off == off + hdr_len; */
	/*@ assert (*r_start_off + *r_len) == (off + integer_len); */
	/*@ assert *r_start_off + *r_len <= len; */
	off += hdr_len + data_len;
	/*@ assert (off + remain) <= len; */

	/* An then, the second one, s */
	ret = parse_non_negative_integer(buf, remain, CLASS_UNIVERSAL,
					 ASN1_TYPE_INTEGER,
					 &hdr_len, &data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	integer_len = hdr_len + data_len;
	/*@ assert integer_len <= remain; */
	/*@ assert (off + remain) <= len; */
	/*@ assert (off + integer_len) <= len; */
	remain -= integer_len;
	buf += hdr_len + data_len;
	*s_start_off = off + hdr_len;
	/*@ assert *s_start_off == off + hdr_len; */
	*s_len = data_len;
	/*@ assert *s_len == data_len; */
	/*@ assert *s_start_off == off + hdr_len; */
	/*@ assert (*s_start_off + *s_len) == (off + integer_len); */
	/*@ assert *s_start_off + *s_len <= len; */
	off += integer_len;

	/*
	 * Check there is nothing remaining in the bitstring
	 * after the two integers
	 */
	if (remain != 0) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert saved_sig_len <= len; */
	/*@ assert *r_start_off + *r_len <= len; */
	/*@ assert *s_start_off + *s_len <= len; */
	*eaten = saved_sig_len;

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->ecdsa.r_raw_off,
	    params->ecdsa.r_raw_len,
	    params->ecdsa.s_raw_off,
	    params->ecdsa.s_raw_len;
  @*/
static int parse_sig_ecdsa(sig_params *params,
			   const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 r_start_off = 0, r_len= 0, s_start_off = 0, s_len = 0;
	const u8 *buf =  cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = sig_dsa_based_extract_r_s(buf, len, &r_start_off, &r_len,
					&s_start_off, &s_len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	params->ecdsa.r_raw_off = off + r_start_off;
	params->ecdsa.r_raw_len = r_len;
	params->ecdsa.s_raw_off = off + s_start_off;
	params->ecdsa.s_raw_len = s_len;
	ret = 0;

out:
	return ret;
}

/*
 * SM2 signature and ECDSA signature have exactly the same structre, i.e. a
 * bitstring which encapsulates a sequence of 2 integers (r and s).
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->sm2.r_raw_off,
	    params->sm2.r_raw_len,
	    params->sm2.s_raw_off,
	    params->sm2.s_raw_len;
  @*/
static int parse_sig_sm2(sig_params *params,
			 const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 r_start_off = 0, r_len = 0, s_start_off = 0, s_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = sig_dsa_based_extract_r_s(buf, len, &r_start_off, &r_len,
					&s_start_off, &s_len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	params->sm2.r_raw_off = off + r_start_off;
	params->sm2.r_raw_len = r_len;
	params->sm2.s_raw_off = off + s_start_off;
	params->sm2.s_raw_len = s_len;
	ret = 0;

out:
	return ret;
}


/*
 * Handle parsing of RSA PKCS#1 v1.5 signature structure i.e. the opaque
 * content of the bitstring.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->rsa_pkcs1_v1_5.sig_raw_off,
	    params->rsa_pkcs1_v1_5.sig_raw_len;
  @*/
static int parse_sig_rsa_pkcs1_v15(sig_params *params,
				   const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 bs_data_start_off = 0, bs_data_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_sig_rsa_helper(buf, len,
				   &bs_data_start_off, &bs_data_len,
				   eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	/*
	 * We can now record start and length of data carried in the signature
	 * bitstring, i.e. usually the raw big endian encoded integer value (no
	 * ASN.1 integer encoding) corresponding to the signature.
	 */
	params->rsa_pkcs1_v1_5.sig_raw_off = off + bs_data_start_off;
	params->rsa_pkcs1_v1_5.sig_raw_len = bs_data_len;

out:
	return ret;
}

/*
 * Handle parsing of RSASSA PSS signature structure i.e. the opaque
 * content of the bitstring.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->rsa_ssa_pss.sig_raw_off,
	    params->rsa_ssa_pss.sig_raw_len;
  @*/
static int parse_sig_rsa_ssa_pss(sig_params *params,
				 const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 bs_data_start_off = 0, bs_data_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_sig_rsa_helper(buf, len,
				   &bs_data_start_off, &bs_data_len,
				   eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	/*
	 * We can now record start and length of data carried in the signature
	 * bitstring, i.e. usually the raw big endian encoded integer value (no
	 * ASN.1 integer encoding) corresponding to the signature.
	 */
	params->rsa_ssa_pss.sig_raw_off = off + bs_data_start_off;
	params->rsa_ssa_pss.sig_raw_len = bs_data_len;

out:
	return ret;
}

/*
 * Handle parsing of 9796 pad 2 signature structure i.e. the opaque
 * content of the bitstring.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->rsa_9796_2_pad.sig_raw_off,
	    params->rsa_9796_2_pad.sig_raw_len;
  @*/
static int parse_sig_rsa_9796_2_pad(sig_params *params,
				    const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 bs_data_start_off = 0, bs_data_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_sig_rsa_helper(buf, len,
				   &bs_data_start_off, &bs_data_len,
				   eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	/*
	 * We can now record start and length of data carried in the signature
	 * bitstring, i.e. usually the raw big endian encoded integer value (no
	 * ASN.1 integer encoding) corresponding to the signature.
	 */
	params->rsa_9796_2_pad.sig_raw_off = off + bs_data_start_off;
	params->rsa_9796_2_pad.sig_raw_len = bs_data_len;

out:
	return ret;
}

/*
 * Handle parsing of belgian rsa signature structure i.e. the opaque
 * content of the bitstring.
 */
/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->belgian_rsa.sig_raw_off,
	    params->belgian_rsa.sig_raw_len;
  @*/
static int parse_sig_rsa_belgian(sig_params *params,
				 const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 bs_data_start_off = 0, bs_data_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = parse_sig_rsa_helper(buf, len,
				   &bs_data_start_off, &bs_data_len,
				   eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	/*
	 * We can now record start and length of data carried in the signature
	 * bitstring, i.e. usually the raw big endian encoded integer value (no
	 * ASN.1 integer encoding) corresponding to the signature.
	 */
	params->belgian_rsa.sig_raw_off = off + bs_data_start_off;
	params->belgian_rsa.sig_raw_len = bs_data_len;

out:
	return ret;
}



/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, cert+(..), params);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (params == \null) ==> \result < 0;
  @
  @ assigns *eaten,
	    params->dsa.r_raw_off,
	    params->dsa.r_raw_len,
	    params->dsa.s_raw_off,
	    params->dsa.s_raw_len;
  @*/
static int parse_sig_dsa(sig_params *params,
			 const u8 *cert, u32 off, u32 len, u32 *eaten)
{
	u32 r_start_off = 0, r_len=0, s_start_off = 0, s_len = 0;
	const u8 *buf = cert + off;
	int ret;

	if ((params == NULL) || (cert == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \valid_read(buf + (0 .. len - 1)); */

	ret = sig_dsa_based_extract_r_s(buf, len, &r_start_off, &r_len,
					&s_start_off, &s_len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert *eaten <= len; */

	params->dsa.r_raw_off = off + r_start_off;
	params->dsa.r_raw_len = r_len;
	params->dsa.s_raw_off = off + s_start_off;
	params->dsa.s_raw_len = s_len;
	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((u64)off + (u64)len) <= MAX_UINT32;
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (off .. (off + len - 1)));
  @ requires (sig_alg != \null) ==> \valid_read(sig_alg) && \valid_function(sig_alg->parse_sig);
  @ requires (\initialized(&ctx->sig_alg));
  @ requires \valid(eaten);
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..), sig_alg, eaten);
  @
  @ ensures \result <= 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @ ensures (ctx == \null) ==> \result < 0;
  @ ensures (sig_alg == \null) ==> \result < 0;
  @ ensures (eaten == \null) ==> \result < 0;
  @
  @ assigns *eaten, *ctx;
  @*/
static int parse_x509_signatureValue(cert_parsing_ctx *ctx,
				     const u8 *cert, u32 off, u32 len,
				     const _sig_alg *sig_alg, u32 *eaten)
{
	u32 saved_off = off;
	int ret;

	if ((cert == NULL) || (len == 0) || (sig_alg == NULL) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	if (sig_alg->parse_sig == NULL) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert sig_alg->parse_sig \in {
		  parse_sig_ed448,
		  parse_sig_ed25519,
		  parse_sig_ecdsa,
		  parse_sig_sm2,
		  parse_sig_dsa,
		  parse_sig_rsa_pkcs1_v15,
		  parse_sig_rsa_ssa_pss,
		  parse_sig_rsa_9796_2_pad,
		  parse_sig_rsa_belgian,
		  parse_sig_gost94,
		  parse_sig_gost2001,
		  parse_sig_gost2012_512,
		  parse_sig_gost2012_256,
		  parse_sig_bign,
		  parse_sig_monkey }; @*/
	/*@ calls parse_sig_ed448,
		  parse_sig_ed25519,
		  parse_sig_ecdsa,
		  parse_sig_sm2,
		  parse_sig_dsa,
		  parse_sig_rsa_pkcs1_v15,
		  parse_sig_rsa_ssa_pss,
		  parse_sig_rsa_9796_2_pad,
		  parse_sig_rsa_belgian,
		  parse_sig_gost94,
		  parse_sig_gost2001,
		  parse_sig_gost2012_512,
		  parse_sig_gost2012_256,
		  parse_sig_bign,
		  parse_sig_monkey; @*/
	ret = sig_alg->parse_sig(&(ctx->sig_alg_params), cert, off, len, eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ctx->sig_start = saved_off;
	ctx->sig_len = *eaten;
	ret = 0;

out:
	return ret;
}

/*
 * The goal being to zeroify all the fields of a given structure (not a buffer)
 * using a function, we did not manage to do that using memset() in Typed memory
 * model and at the same time validate assigns clause. I tried and reimplement
 * a specific function but conversion of the structure to a buffer to initialize
 * one by one all the bytes of the structure result in an inability to validate
 * assigns clause for the structure in the function. A good amount of time was
 * spent on annotations strategies w/o success.
 *
 * Until one finds a better solution, a decent workaround has been found with
 * the following function, which internally declares a structure with a static
 * initializer and returns that (zeroized) structure by value. In a caller, the
 * variable to be zeroized can just be overridden with the result of the
 * function. This is not generic but sufficient for the need we have in the
 * parser.
 */
/*@
  @ assigns \nothing;
  @*/
static cert_parsing_ctx get_zeroized_ctx_val(void)
{
	cert_parsing_ctx zeroized_ctx = { 0 };

	return zeroized_ctx;
}

/*@
  @ requires ((len > 0) && (cert != \null)) ==> \valid_read(cert + (0 .. (len - 1)));
  @ requires \valid(ctx);
  @ requires \separated(ctx, cert+(..));
  @
  @ ensures \result <= 0;
  @ ensures (len == 0) ==> \result < 0;
  @ ensures (ctx == 0) ==> \result < 0;
  @ ensures (cert == \null) ==> \result < 0;
  @
  @ assigns *ctx;
  @*/
int parse_x509_cert(cert_parsing_ctx *ctx, const u8 *cert, u32 len)
{
	u32 seq_data_len = 0;
	u32 eaten = 0;
	u32 off = 0;
	const _sig_alg *sig_alg = NULL;
	int ret;

	if ((cert == NULL) || (len == 0) || (ctx == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	*ctx = get_zeroized_ctx_val();

	/*
	 * Parse beginning of buffer to verify it's a sequence and get
	 * the length of the data it contains.
	 */
	ret = parse_id_len(cert, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &eaten, &seq_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	len -= eaten;
	off += eaten;
	/*@ assert off + len <= MAX_UINT32; */

	/*
	 * We do expect advertised length to match what now remains in buffer
	 * after the sequence header we just parsed.
	 */
	if (seq_data_len != len) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Parse first element of the sequence: tbsCertificate */
	ret = parse_x509_tbsCertificate(ctx, cert, off, len, &sig_alg, &eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \initialized(&(ctx->sig_alg)); */
	/*@ assert ctx->tbs_sig_alg_start < off + eaten; */

	ctx->tbs_start = off;
	ctx->tbs_len = eaten;

	len -= eaten;
	off += eaten;

	/*@ assert ctx->tbs_sig_alg_start <= off; */

	/* Parse second element of the sequence: signatureAlgorithm */
	ret = parse_x509_signatureAlgorithm(ctx, cert, off, len, &eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*@ assert \initialized(&(ctx->sig_alg)); */

	len -= eaten;
	off += eaten;

	/* Parse second element of the sequence: signatureValue */
	ret = parse_x509_signatureValue(ctx, cert, off, len, sig_alg, &eaten);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Check there is nothing left behind */
	if (len != eaten) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*@
  @ requires ((len > 0) && (buf != \null)) ==> \valid_read(buf + (0 .. (len - 1)));
  @ requires \valid(eaten);
  @ requires \separated(eaten, buf+(..), ctx);
  @
  @ ensures \result <= 1;
  @ ensures (eaten == \null) ==> \result < 0;
  @ ensures (buf == \null) ==> \result < 0;
  @ ensures (\result == 0) ==> (*eaten <= len);
  @ ensures (\result == 0) ==> (*eaten > 0);
  @
  @ assigns *eaten, *ctx;
 */
int parse_x509_cert_relaxed(cert_parsing_ctx *ctx, const u8 *buf, u32 len, u32 *eaten)
{
	u32 seq_data_len = 0;
	u32 rbytes = 0;
	int ret;

	if ((ctx == NULL) || (buf == NULL) || (len == 0) || (eaten == NULL)) {
		ret = -__LINE__;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/*
	 * Parse beginning of buffer to verify it's a sequence and get
	 * the length of the data it contains.
	 */
	ret = parse_id_len(buf, len, CLASS_UNIVERSAL, ASN1_TYPE_SEQUENCE,
			   &rbytes, &seq_data_len);
	if (ret) {
		ret = 1;
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	/* Certificate has that exact length */
	*eaten = rbytes + seq_data_len;

	/* Parse it */
	ret = parse_x509_cert(ctx, buf, rbytes + seq_data_len);
	if (ret) {
		ERROR_TRACE_APPEND(__LINE__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}


#if defined(__FRAMAC__)

/* This dummy main allows testing */

#include "__fc_builtin.h"
#define RAND_BUF_SIZE MAX_UINT32

int main(int argc, char *argv[]) {
	u8 buf[RAND_BUF_SIZE];
	cert_parsing_ctx ctx;
	u32 len;
	int ret;

	/*@ assert \valid(buf + (0 .. (RAND_BUF_SIZE - 1))); */
	Frama_C_make_unknown((char *)buf, RAND_BUF_SIZE);

	len = Frama_C_unsigned_int_interval(0, RAND_BUF_SIZE);
	/*@ assert 0 <= len <= RAND_BUF_SIZE; */

	ret = parse_x509_cert(&ctx, buf, len);

	return ret;
}

#elif defined(__IKOS__)

#include <ikos/analyzer/intrinsic.h>
#define RAND_BUF_SIZE MAX_UINT32

int main(int argc, char *argv[]) {
	u8 buf[RAND_BUF_SIZE];
	cert_parsing_ctx ctx;
	u32 len;
	int ret;

	__ikos_abstract_mem(buf, RAND_BUF_SIZE);

	len = __ikos_nondet_uint();
	__ikos_assume(len <= RAND_BUF_SIZE);

	ret = parse_x509_cert(&ctx, buf, len);

	return ret;
}

#endif
