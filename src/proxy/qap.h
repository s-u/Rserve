#ifndef QAP_H__
#define QAP_H__

typedef struct phdr {   /* always 16 bytes */
    int cmd;    /* command */
    int len;    /* length of the packet minus header (ergo -16) */
    int msg_id; /* message id (since 1.8) [WAS:data offset behind header (ergo usually 0)] */
    int res; /* high 32-bit of the packet length (since 0103
		and supported on 64-bit platforms only)
		aka "lenhi", but the name was not changed to
		maintain compatibility */
} qap_hdr_t;

/* macros for handling the first int - split/combine (24-bit version only!) */
#define PAR_TYPE(X) ((X) & 255)
#define PAR_LEN(X) (((unsigned int)(X)) >> 8)
#define PAR_LENGTH PAR_LEN
#define SET_PAR(TY,LEN) ((((unsigned int) (LEN) & 0xffffff) << 8) | ((TY) & 255))

#define CMD_STAT(X) (((X) >> 24)&127) /* returns the stat code of the response */
#define SET_STAT(X,s) ((X) | (((s) & 127) << 24)) /* sets the stat code */

#define CMD_RESP 0x10000  /* all responses have this flag set */

#define RESP_OK (CMD_RESP|0x0001) /* command succeeded; returned parameters depend
                                     on the command issued */
#define RESP_ERR (CMD_RESP|0x0002) /* command failed, check stats code
                                      attached string may describe the error */

#define CMD_OOB  0x20000  /* out-of-band data - i.e. unsolicited messages */
#define OOB_SEND (CMD_OOB | 0x1000) /* OOB send - unsolicited SEXP sent from the R instance to the client. 12 LSB are reserved for application-specific code */
#define OOB_MSG  (CMD_OOB | 0x2000) /* OOB message - unsolicited message sent from the R instance to the client requiring a response. 12 LSB are reserved for application-specific code */

#define IS_OOB_SEND(X)  (((X) & 0x0ffff000) == OOB_SEND)
#define IS_OOB_MSG(X)   (((X) & 0x0ffff000) == OOB_MSG)
#define OOB_USR_CODE(X) ((X) & 0xfff)

/* flag for create_server: Use QAP object-cap mode */
#define SRV_QAP_OC 0x40
/* mask of all flags that are relevant to QAP (so they can be passed through) */
#define SRV_QAP_FLAGS (SRV_QAP_OC)

#define ERR_auth_failed      0x41
#define ERR_conn_broken      0x42

#define CMD_OCcall       0x00f
#define CMD_OCinit  0x434f7352

#define DT_SEXP       10
#define DT_LARGE      64

#define XT_STR           3
#define XT_VECTOR        16
#define XT_LIST_TAG      21
#define XT_LANG_NOTAG    22
#define XT_LANG_TAG      23
#define XT_ARRAY_INT     32
#define XT_ARRAY_STR     34
#define XT_RAW           37

#define XT_LARGE         64
#define XT_HAS_ATTR      128

#endif
