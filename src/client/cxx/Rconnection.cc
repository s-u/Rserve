/*
 *  C++ Interface to Rserve
 *  Copyright (C) 2004-8 Simon Urbanek, All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; version 2.1 of the License
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Leser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Although this code is licensed under LGPL v2.1, we strongly encourage
 *  everyone modifying this software to contribute back any improvements and
 *  bugfixes to the project for the benefit all other users. Thank you.
 * 
 *  $Id: Rconnection.cc 301 2011-01-07 16:32:45Z urbanek $
 */

/* external defines:
   SWAPEND  - needs to be defined for platforms with inverse endianess related to Intel
   see also SOCK_ERROR, MAIN and other defines in sisocks.h
*/

/* locally generated status error and return codes:
   -1  - operation failed (e.g. connect failed)
   -2  - handhake failed
   -3  - invalid ID string
   -4  - protocol not supported
   -5  - not connected
   -6  - - unused -
   -7  - remote connection close
   -8  - malformed packet
   -9  - send error
   -10 - out of memory
   -11 - operation is unsupported (e.g. unix login while crypt is not linked)
   -12 - eval didn't return a SEXP (possibly the server is too old/buggy or crashed)
 */
#include "Rconnection.h"

#include <stdio.h>
#include "sisocks.h"
#ifdef unix
#include <sys/un.h>
#include <unistd.h>
#else
#define AF_LOCAL -1
#endif
#if defined HAVE_NETINET_TCP_H && defined HAVE_NETINET_IN_H
#define CAN_TCP_NODELAY
#include <netinet/tcp.h>
#include <netinet/in.h>
#endif
#ifdef Win32
#define CAN_TCP_NODELAY
#endif

#include "Rsrv.h"

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

// NOTE: 0103 compatibility has not been established! use at your own risk!
static const char *myID = "Rsrv0103QAP1"; /* this client supports up to protocol version 0103 */

#define IS_LIST_TYPE_(TYPE) ((TYPE) == XT_LIST || (TYPE) == XT_LIST_NOTAG || (TYPE) == XT_LIST_TAG)
#define IS_SYMBOL_TYPE_(TYPE) ((TYPE) == XT_SYM || (TYPE) == XT_SYMNAME)

static Rexp *new_parsed_Rexp(unsigned int *d, Rmessage *msg) {
    int type=ptoi(*d)&0x3f;
#ifdef DEBUG_CXX
    printf("new_parsed_Rexp(%p, %p) type=%d\n", d, msg, type);
#endif
    if (type==XT_ARRAY_INT || type==XT_INT)
        return new Rinteger(d,msg);
    if (type==XT_ARRAY_BOOL || type==XT_BOOL)
        return new Rboolean(d,msg);
    if (type==XT_ARRAY_DOUBLE || type==XT_DOUBLE)
        return new Rdouble(d,msg);
    if (IS_LIST_TYPE_(type))
        return new Rlist(d,msg);
    if (type==XT_VECTOR)
        return new Rvector(d,msg);
    if (type==XT_STR)
        return new Rstring(d,msg);
    if (type==XT_SYM || type==XT_SYMNAME)
        return new Rsymbol(d,msg);
    if (type==XT_ARRAY_STR)
        return new Rstrings(d,msg);
	if (type==XT_RAW)
		return new Rraw(d,msg);
    return new Rexp(d,msg);
}

Rexp *new_parsed_Rexp_from_Msg(Rmessage *msg) {
    int hl=1;
    unsigned int *hp=msg->par[0];
    Rsize_t plen=hp[0]>>8;
    if ((hp[0]&DT_LARGE)>0) {
        hl++;
        plen|=((Rsize_t)hp[1])<<24;
    }
    return new_parsed_Rexp(hp+hl,msg);
}    

Rmessage::Rmessage() {
    complete=0;
    data=0;
    len=0;
}

Rmessage::Rmessage(int cmd) {
    memset(&head,0,sizeof(head));
    head.cmd = cmd;
    data=0;
    len=0;
    complete=1;
}

Rmessage::Rmessage(int cmd, const char *txt) {
    memset(&head,0,sizeof(head));
    int tl=strlen(txt)+1;
    if ((tl&3)>0)
        tl=(tl+4)&0xffffc; // allign the text
    len=tl+4; // message length is tl + 4 (short format only)
    head.cmd=cmd;
    head.len=len;
    data=(char*)malloc(tl+16);
    memset(data,0,tl+16);
    *((int*)data)=itop(SET_PAR(DT_STRING,tl));
    strcpy(data+4,txt);
    complete=1;
}

Rmessage::Rmessage(int cmd, const void *buf, int dlen, int raw_data) {
    memset(&head,0,sizeof(head));
    len=(raw_data)?dlen:(dlen+4);
    head.cmd=cmd;
    head.len=len;
    data=(char*)malloc(len);
    memcpy(data, (raw_data)?buf:((char*)buf+4), dlen);
    if (!raw_data)
        *((int*)data)=itop(SET_PAR(DT_BYTESTREAM,dlen));  
    complete=1;
}  

Rmessage::Rmessage(int cmd, int i) {
    memset(&head,0,sizeof(head));
    len=8; // DT_INT+len (4) + payload-1xINT (4)
    head.cmd=cmd;
    head.len=len;
    data=(char*)malloc(8);
    *((int*)data)=itop(SET_PAR(DT_INT,4));
    ((int*)data)[1]=itop(i);
    complete=1;
}
    
Rmessage::~Rmessage() {
    if(data) free(data);
    complete=0;
}
    
int Rmessage::read(int s) {
    complete=0;
    int n=recv(s,(char*)&head,sizeof(head),0);
    if (n!=sizeof(head)) {
        closesocket(s); s=-1;
        return (n==0)?-7:-8;
    }
    Rsize_t i=len=head.len=ptoi(head.len);        
    head.cmd=ptoi(head.cmd);
    head.dof=ptoi(head.dof);
    head.res=ptoi(head.res);
    if (head.dof>0) { // skip past DOF if present
            char sb[256];
        int k=head.dof;
        while (k>0) {
            n=recv(s,(char*)sb,(k>256)?256:k,0);
            if (n<1) {
                closesocket(s); s=-1;
                return -8; // malformed packet
            }
            k-=n;
        }
    }
    if (i>0) {
        data=(char*) malloc(i);
        if (!data) {
            closesocket(s); s=-1;
            return -10; // out of memory
        }
        char *dp=data;
        while(i>0 && (n=recv(s,(char*)dp,i,0))>0) {
            dp+=n;
            i-=n;
        }
        if (i>0) {
            closesocket(s); s=-1;
            return -8;
        }
    }
    parse();
    complete=1;
    return 0;
}

void Rmessage::parse() {
    pars=0;
    if (len<4) return;
    char *c=data, *eop=c+len;
    while (c<eop) {
        int hs=4;
        unsigned int *pp=(unsigned int*)c;
        unsigned int p1=ptoi(pp[0]);
        
        Rsize_t len=p1>>8;
        if ((p1&DT_LARGE)>0) {
            hs+=4;
            unsigned int p2=ptoi(pp[1]);
            len|=((Rsize_t)p2)<<24;
        }
#ifdef DEBUG_CXX
        printf("  par %d: %d length %d\n", pars, p1&0x3f, len);
#endif
        par[pars++]=(unsigned int*)c;
        c+=hs;
        c+=len;
        if (pars>15) break; // max 16 pars
    }
}

int Rmessage::send(int s) {
    int failed=0;
    head.cmd=itop(head.cmd);
    head.len=itop(head.len);
    head.dof=itop(head.dof);
    head.res=itop(head.res);
    if (::send(s,(char*)&head,sizeof(head),0)!=sizeof(head))
        failed=-1;
    if (!failed && len>0 && (Rsize_t)::send(s,data,len,0)!=len)
        failed=-1;
    head.cmd=ptoi(head.cmd);
    head.len=ptoi(head.len);
    head.dof=ptoi(head.dof);
    head.res=ptoi(head.res);
    return failed;
}

Rexp::Rexp(Rmessage *msg) {
#ifdef DEBUG_CXX
    printf("new Rexp@%x\n", this);
#endif
    master=0; rcount=0; attr=0; attribs=0;
    this->msg=msg;
    int hl=1;
    unsigned int *hp=msg->par[0];
    Rsize_t plen=hp[0]>>8;
    if ((hp[0]&DT_LARGE)>0) {
        hl++;
        plen|=((Rsize_t)hp[1])<<24;
    }
    next=parse(hp+hl);
}
    
Rexp::Rexp(unsigned int *pos, Rmessage *msg) {
#ifdef DEBUG_CXX
    printf("new Rexp@%x\n", this);
#endif
    attr=0; master=0; this->msg=msg; rcount=0; attribs=0;
    next=parse(pos);
}

Rexp::Rexp(int type, const char *data, int len, Rexp *attr) {
    this->attr=attr; master=this; rcount=0; attribs=0;
    this->type=type;
    this->msg=0;
    if (len>0) {
#ifdef DEBUG_CXX
        fprintf(stderr, "Rexp::Rexp %p: allocating %d bytes\n", this, len);
#endif
        this->data=(char*) malloc(len);
        memcpy(this->data, data, len);
        this->len=len;
    } else
        this->len=0;
    next=(char*)data+this->len;
}

Rexp::~Rexp() {
#ifdef DEBUG_CXX
    printf("releasing Rexp@%p\n", this);
#endif
    if (attr)
        delete(attr);
    attr=0;
    if (master) {
        if (master==this) {
            free(data); len=0;
        } else
            master->rcount--;
        master=0;
    }
    if (msg) {
        if (rcount>0)
            fprintf(stderr, "WARNING! Rexp master %lx delete requested, but %d object(s) are using our memory - refusing to free, leaking...\n", (long)this, rcount);
        else
            delete(msg);
    }
    msg=0;
}

void Rexp::set_master(Rexp *m) {
    if (master) master->rcount--;
    master=m;
    if (m) m->rcount++;
}
    
char *Rexp::parse(unsigned int *pos) { // plen is not used
    this->pos=pos;
    int hl=1;
    unsigned int p1=ptoi(pos[0]);
    len=p1>>8;
    if ((p1&XT_LARGE)>0) {
        hl++;
        len|=((Rsize_t)(ptoi(pos[1])))<<24;
    }
    data=(char*)(pos+hl);
    if (p1&XT_HAS_ATTR) {
        attr=new_parsed_Rexp((unsigned int*)data, 0);
        len-=attr->next-data;
        data=attr->next;
        if (master || msg)
            attr->set_master(master?master:this);
    }
    type=p1&0x3f;
#ifdef DEBUG_CXX
    printf("Rexp(type=%d, len=%d, attr=%p)\n", type, len, attr);
#endif
    return data+len;
}

Rsize_t Rexp::storageSize() const {
    Rsize_t total_len = len + (attr ? attr->storageSize() : 0);
    return total_len + ((total_len>0x7fffff) ? 8 : 4);
}

void Rexp::store(char *buf) const {
    int hl=4;
    unsigned int *i = (unsigned int*)buf;
    Rsize_t total_len = len + (attr ? attr->storageSize() : 0);
    i[0]=SET_PAR(type, total_len);
    i[0]=itop(i[0]);
    if (total_len>0x7fffff) {
        buf[0]|=XT_LARGE;
        i[1]=itop(total_len>>24);
        hl+=4;
    }
    if (attr) {
	i[0] |= XT_HAS_ATTR;
	attr->store(buf + hl);
	memcpy(buf + hl + attr->storageSize(), data, len);
    } else memcpy(buf+hl, data, len);
}

Rexp *Rexp::attribute(const char *name) {
    return (attr && IS_LIST_TYPE_(attr->type)) ? ((Rlist*)attr)->entryByTagName(name) : 0;
}

const char **Rexp::attributeNames() {
    if (!attr || !IS_LIST_TYPE_(attr->type))
        return 0;
    if (attribs == 0) {
        // let us cache attribute names
        Rlist *l = (Rlist*) attr;
        while (l && (IS_LIST_TYPE_(l->type))) {
	    if (l->tag && IS_SYMBOL_TYPE_(l->tag->type)) attribs++;
	    l = l->tail;
	}
        attrnames = (const char**) malloc(sizeof(char*)*(attribs+1));
        l = (Rlist*) attr;
        while (l && IS_LIST_TYPE_(l->type)) {
            if (l->tag && IS_SYMBOL_TYPE_(l->tag->type))
                attrnames[attribs++] = ((Rsymbol*)l->tag)->symbolName();
            l = l->tail;
        }
        attrnames[attribs] = 0;
    }
    return attrnames;
}

void Rinteger::fix_content() {
    if (len<0 || !data) return;
#ifdef SWAPEND
    int *i = (int*) data;
    int *j = (int*) (data+len);
    while (i<j) { *i=ptoi(*i); i++; }
#endif
}

double R_ValueOfNA() { // binary definition, see R source code
    double d;
#ifdef SWAPEND
    *((unsigned int*)(&d) + 0) = 0x7ff00000;
    *((unsigned int*)(&d) + 1) = 1954;
#else
    *((unsigned int*)(&d) + 1) = 0x7ff00000;
    *((unsigned int*)(&d) + 0) = 1954;
#endif
    return d;
}
const double NA_DOUBLE = R_ValueOfNA();

void Rdouble::fix_content() {
    if (len<0 || !data) return;
#ifdef SWAPEND
    double *i = (double*) data;
    double *j = (double*) (data+len);
    while (i<j) { *i=ptod(*i); i++; }
#endif
}

void Rsymbol::fix_content() {
    if (type == XT_SYM && *data==3) name=data+4; // normally the symbol should consist of a string SEXP specifying its name - no further content is defined as of now
    if (type == XT_SYMNAME) name=data; // symname consists solely of the name
#ifdef DEBUG_CXX
    printf("SYM %p \"%s\"\n", this, name);
#endif
}

Rlist::Rlist(const std::vector<Rexp*> &tags,
	     const std::vector<Rexp*> &entries) : Rexp(XT_LIST_TAG) {
    // Create Rlist, copying tags and entries from args
    // Set length of data buffer
			 Rsize_t len = 0;
#undef min // apparently windows redefines this
	std::vector<Rexp*>::size_type count = std::min(tags.size(),
		entries.size());
    for(std::vector<Rexp*>::size_type i = 0; i != count; i++)
	len += tags[i]->storageSize() + entries[i]->storageSize();

    // Create data buffer and copy rexps into it
    if (len > 0) {
#ifdef DEBUG_CXX
	fprintf(stderr, "Rlist::Rlist %p: allocating %d bytes\n",
		this, len);
#endif
	data = (char*)malloc(len);
	Rsize_t curpos = 0;
	for(std::vector<Rexp*>::size_type i = 0; i != count; i++) {
	    entries[i]->store(data + curpos);
	    curpos += entries[i]->storageSize();
	    tags[i]->store(data + curpos);
	    curpos += tags[i]->storageSize();
	}
    }
	    
    // Update class variables
    this->data = data;
    this->len = len;
    this->tag = this->head = this->tail = 0;
    fix_content();
}

Rlist::~Rlist() {
    if (head) delete(head);
    if (tail) delete(tail);
    if (tag) delete(tag);
}

void Rlist::fix_content() {
    char *ptr = data;
    char *eod = data+len;
#ifdef DEBUG_CXX
    printf("Rlist::fix_content data=%p, type=%d\n", ptr, type);
#endif
    if (type == XT_LIST) { /* old-style lists */
      head=new_parsed_Rexp((unsigned int*)ptr,0);
      if (head) {
        ptr=head->next;
        if (ptr<eod) {
	  tail=(Rlist*)new_parsed_Rexp((unsigned int*)ptr,0);
	  if (tail) {
	    ptr=tail->next;
	    if (ptr<eod)
	      tag=new_parsed_Rexp((unsigned int*)ptr,0);
	    if (tail->type!=XT_LIST) {
	      // if tail is not a list, then something is wrong - just delete it
	      delete(tail); tail=0;
	    }
	  }
        }
      }
    } else if (type == XT_LIST_NOTAG) { /* new style list w/o tags */
      Rlist *lt = this;
      int n = 0;
      while (ptr < eod) {
	Rexp *h = new_parsed_Rexp((unsigned int*) ptr, 0);
	if (!h) break;
	if (n)
	  lt = lt->tail = new Rlist(type, h, 0, h->next, msg);
	else
	  lt->head = h;
	n++;
	ptr = h->next;
      }
    } else if (type == XT_LIST_TAG) { /* new style list with tags */
      Rlist *lt = this;
      int n = 0;
      while (ptr < eod) {
	Rexp *h = new_parsed_Rexp((unsigned int*) ptr, 0);
#ifdef DEBUG_CXX
	printf(" LIST_TAG: n=%d, ptr=%p, h=%p\n", n, ptr, h);
#endif
	if (!h) break;
	ptr = h->next;
	Rexp *t = new_parsed_Rexp((unsigned int*) ptr, 0);
#ifdef DEBUG_CXX
	printf("          tag=%p (ptr=%p)\n", t, ptr);
#endif
	if (!t) break;
	if (n)
	    lt = lt->tail = new Rlist(type, h, t, t->next, 0);
	else {
	  lt->head = h;
	  lt->tag = t;
	}
	ptr = t->next;
	n++;
      }
      next = ptr;
    }
#ifdef DEBUG_CXX
    printf(" end of list %p, ptr=%p\n", this, ptr);
#endif
}

Rvector::~Rvector() {
    int i=0;
    while(i<count) {
        if (cont[i]) delete(cont[i]);
        i++;
    }
    if (strs) free(strs);
    free(cont);
}

char **Rvector::strings() {
    if (strs) return strs;
    int i=0, sc=0;
    while (i<count) {
        if (cont[i] && cont[i]->type==XT_STR) sc++;
        i++;
    }
    if (sc==0) return 0;
    strs=(char**)malloc(sizeof(char*)*(sc+1));
    i=0; sc=0;
    while (i<count) {
        if (cont[i] && cont[i]->type==XT_STR) strs[sc++]=((Rstring*)cont[i])->string();
        i++;
    }
    strs[sc]=0;
    return strs;
}

int Rvector::indexOf(Rexp *exp) {
    int i=0;
    while (i<count) {
        if (cont[i]==exp) return i;
        i++;
    }
    return -1;
}

int Rvector::indexOfString(const char *str) {
    int i=0;
    while (i<count) {
        if (cont[i] && cont[i]->type==XT_STR && !strcmp(((Rstring*)cont[i])->string(),str)) return i;
        i++;
    }
    return -1;
}

Rraw::Rraw(const std::vector<char> &v) : Rexp(XT_RAW) {
	// Create new Rraw (raw data) Rexp from vector of characters
	bytecount = v.size();
	len = bytecount + 4;
	next = data + len;
	if (len == 0)
		return;

	data = (char*)malloc(len);
	unsigned int swapped_bytecount = itop(bytecount);
	memcpy(data, (char *)(&swapped_bytecount), sizeof(unsigned int));
	memcpy(data + sizeof(unsigned int), &v.front(), v.size());
}

Rstrings::Rstrings(const std::vector<std::string> &v) : Rexp(XT_ARRAY_STR) {
    // Create from C strings
    // Set length of data buffer
    Rsize_t len = 0;
    for(std::vector<std::string>::const_iterator it = v.begin();
		it != v.end(); ++it) {
			len += it->length() + 1;
	}
    
    // Create data buffer and copy strings into it
	if (len > 0) {
#ifdef DEBUG_CXX
		fprintf(stderr, "Rstrings::Rstrings %p: allocating %d bytes\n",
			this, len);
#endif
		data = (char*)malloc(len);

		Rsize_t curpos = 0;
		for(std::vector<std::string>::const_iterator it = v.begin();
			it != v.end(); ++it) {
				memcpy(data + curpos, it->data(), it->length());
				curpos += it->length();
				data[curpos++] = '\0';
		}
	}
    
	// Update class variables
	this->next = (char*)data + len;
	this->len = len;
	this->data = data;
	decode();
}

int Rstrings::indexOfString(const char *str) {
    unsigned int i = 0;
    while (i < nel) {
        if (cont[i] && !strcmp(cont[i], str)) return i;
        i++;
    }
    return -1;
}

const char* NA_STRING = (char *)NaStringRepresentation;

Rvector::Rvector(const std::vector<Rexp*> &v, Rexp *attr)
    : Rexp(XT_VECTOR, 0, 0, attr) {
    // Create an Rvector, copy objects completely from v
    // Set length of data buffer
    Rsize_t len = 0;
    for(std::vector<Rexp*>::const_iterator it = v.begin(); it != v.end(); ++it)
	len += (*it)->storageSize();

    // Create data buffer and copy Rexps into it.  Also update this->cont.
    if (len > 0) {
#ifdef DEBUG_CXX
	fprintf(stderr, "Rvector::Rvector %p: allocating %d bytes\n",
		this, len);
#endif
	data = (char*)malloc(len);
	this->cont = (Rexp **)malloc(v.size() * sizeof(Rexp *));

	Rsize_t curpos = 0;
	for(std::vector<Rexp*>::size_type i = 0; i != v.size(); i++) {
	    v[i]->store(data + curpos);
	    (this->cont)[i] = new_parsed_Rexp((unsigned int*)(data + curpos), 0);
	    curpos += v[i]->storageSize();
	}
    }
    
    // Update non-cont class variables
    this->next = (char*)data + len;
    this->len = len;
    this->data = data;
    this->strs = 0;
    this->count = v.size();
}

Rexp* Rvector::byName(const char *name) {
    /* here we are not using IS_LIST_TYPE_() because XT_LIST_NOTAG is guaranteed to not match */
    if (count < 1 || !attr || (attr->type!=XT_LIST && attr->type != XT_LIST_TAG)) return 0;        
    Rexp *e = ((Rlist*) attr)->head;
    if (((Rlist*) attr)->tag)
        e = ((Rlist*) attr)->entryByTagName("names");
    if (!e || (e->type!=XT_VECTOR && e->type!=XT_ARRAY_STR && e->type!=XT_STR))
        return 0;
    if (e->type == XT_VECTOR) {
        int pos = ((Rvector*)e)->indexOfString(name);
        if (pos>-1 && pos<count) return cont[pos];
    } else if (e->type == XT_ARRAY_STR) {
        int pos = ((Rstrings*)e)->indexOfString(name);
        if (pos>-1 && pos<count) return cont[pos];	
    } else {
        if (!strcmp(((Rstring*)e)->string(),name))
            return cont[0];
    }
    return 0;
}

void Rvector::fix_content() {
    char *ptr = data;
    char *eod = data+len;
    capacity=16;
    cont=(Rexp**) malloc(sizeof(Rexp*)*capacity);
    while (ptr<eod) {
        if (count==capacity) {
            capacity*=2;
            cont=(Rexp**) realloc(cont, sizeof(Rexp*)*capacity);
        }
        cont[count]=new_parsed_Rexp((unsigned int*)ptr,0);
        if (cont[count])
            ptr=cont[count]->next;
        else break;
        count++;
    }
}
    
Rconnection::Rconnection(const char *host, int port) {
    if (!host) host = "127.0.0.1";
    this->host = strdup(host);
    this->port = port;
    family = (port==-1) ? AF_LOCAL : AF_INET;
    s = -1;
    auth = 0;
    salt[0] = '.'; salt[1] = '.';
    session_key = 0;
}
 
Rconnection::Rconnection(Rsession *session) {
    const char *sHost = session->host();
    if (!sHost) sHost="127.0.0.1";
    this->host = strdup(sHost);
    this->port = session->port();
    family = AF_INET;
    s = -1;
    auth = 0;
    salt[0]='.'; salt[1]='.';
    session_key = (char*) malloc(32);
    memcpy(session_key, session->key(), 32);
}

Rconnection::~Rconnection() {
    if (host) free(host);
    host = 0;
    if (s != -1) closesocket(s);
    s = -1;
}
    
int Rconnection::connect() {
#ifdef unix
    struct sockaddr_un sau;
#endif
    SAIN sai;
    char IDstring[33];
    
    if (family==AF_INET) {
        memset(&sai,0,sizeof(sai));
        build_sin(&sai,host,port);
    } else {
#ifdef unix
        memset(&sau,0,sizeof(sau));
        sau.sun_family=AF_LOCAL;
        strcpy(sau.sun_path,host); // FIXME: possible overflow!
#else
	return -11;  // unsupported
#endif
    }
    
    IDstring[32]=0;
    int i;
    
    s=socket(family,SOCK_STREAM,0);
    if (family==AF_INET) {
#ifdef CAN_TCP_NODELAY
        int opt=1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*) &opt, sizeof(opt));
#endif
        i=::connect(s,(SA*)&sai,sizeof(sai));
    }
#ifdef unix
    else
        i=::connect(s,(SA*)&sau,sizeof(sau));
#endif
    if (i==-1) {
        closesocket(s); s=-1;
        return -1; // connect failed
    }
    
    if (session_key) { // resume a session
	int n = send(s, session_key, 32, 0);
	if (n != 32) {
	    closesocket(s); s = -1;
	    return -2; // handshake failed (session key send error)
	}
	Rmessage *msg = new Rmessage();
	int q = msg->read(s);
	delete msg;
	return q;
    }
        
    int n=recv(s,IDstring,32,0);
    if (n!=32) {
        closesocket(s); s=-1;
        return -2; // handshake failed (no IDstring)
    }
    if (strncmp(IDstring,myID,4)) {
        closesocket(s); s=-1;
        return -3; // invalid IDstring
    }
    if (strncmp(IDstring+8,myID+8,4) || strncmp(IDstring+4,myID+4,4)>0) {
        closesocket(s); s=-1;
        return -4; // protocol not supported
    }
    {
      int i=12;
      while (i<32) {
	if (!strncmp(IDstring+i, "ARuc", 4)) auth|=A_required|A_crypt;
	if (!strncmp(IDstring+i, "ARpt", 4)) auth|=A_required|A_plain;
	if (IDstring[i]=='K') {
	  salt[0]=IDstring[i+1];
	  salt[1]=IDstring[i+2];
	}
	i+=4;
      }
    }
    return 0;
}

int Rconnection::disconnect() {
    if (s>-1) {
        closesocket(s);
        s=-1;
    }
    return 0;
}

/**--- low-level functions --*/

int Rconnection::request(Rmessage *msg, int cmd, int len, void *par) {
    struct phdr ph;
    
    if (s==-1) return -5; // not connected
    memset(&ph,0,sizeof(ph));
    ph.len=itop(len);
    ph.cmd=itop(cmd);
    if (send(s,(char*)&ph,sizeof(ph),0)!=sizeof(ph)) {
        closesocket(s); s=-1;
        return -9;
    }
    if (len>0 && send(s,(char*)par,len,0)!=len) {
        closesocket(s); s=-1;
        return -9;
    }
    return msg->read(s);
}

int Rconnection::request(Rmessage *targetMsg, Rmessage *contents) {
    if (s==-1) return -5; // not connected
    if (contents->send(s)) {
        closesocket(s); s=-1;
        return -9; // send error
    }
    return targetMsg->read(s);
}

/** --- high-level functions -- */

int Rconnection::shutdown(const char *key) {
    Rmessage *msg = new Rmessage();
    Rmessage *cm  = key?new Rmessage(CMD_shutdown, key):new Rmessage(CMD_shutdown);
    int res = request(msg, cm);
    delete cm;
    delete msg;
    return res;
}

int Rconnection::assign(const char *symbol, Rexp *exp) {
    Rmessage *msg=new Rmessage();
    Rmessage *cm=new Rmessage(CMD_setSEXP);
    
    int tl=strlen(symbol)+1;
    if (tl&3) tl=(tl+4)&0xfffc;
    Rsize_t xl=exp->storageSize();
    Rsize_t hl=4+tl+4;
    if (xl>0x7fffff) hl+=4;
    cm->data=(char*) malloc(hl+xl);
    cm->head.len=cm->len=hl+xl;
    ((unsigned int*)cm->data)[0]=SET_PAR(DT_STRING, tl);
    ((unsigned int*)cm->data)[0]=itop(((unsigned int*)cm->data)[0]);
    strcpy(cm->data+4, symbol);
    ((unsigned int*)(cm->data+4+tl))[0]=SET_PAR((Rsize_t) ((xl>0x7fffff)?(DT_SEXP|DT_LARGE):DT_SEXP), (Rsize_t) xl);
    ((unsigned int*)(cm->data+4+tl))[0]=itop(((unsigned int*)(cm->data+4+tl))[0]);
    if (xl>0x7fffff)
        ((unsigned int*)(cm->data+4+tl))[1]=itop(xl>>24);
    exp->store(cm->data+hl);
    
    int res=request(msg,cm);
    delete (cm);
    if (res) {
        delete(msg);
        return res;
    }
    if (!res) res = CMD_STAT(msg->command());
    delete(msg);
    return res;
}

int Rconnection::voidEval(const char *cmd) {
    int status=0;
    eval(cmd, &status, 1);
    return status;
}
    
Rexp *Rconnection::eval(const char *cmd, int *status, int opt) { /* opt = 1 -> void eval */
    Rmessage *msg=new Rmessage();
    Rmessage *cmdMessage=new Rmessage((opt&1)?CMD_voidEval:CMD_eval, cmd);
    int res=request(msg,cmdMessage);
    delete (cmdMessage);
    if (opt&1 && !res) {
        if (status) *status=0; // we should put response code here
        delete(msg);
        return 0;
    }
    if ((opt & 1) == 0 && !res && (msg->pars!=1 || (ptoi(msg->par[0][0])&0x3f)!=DT_SEXP)) {
        delete(msg);
        if (status) *status=-12; // returned object is not SEXP
        return 0;
    }
    if (res) {
        delete(msg);
        if (status) *status=res;
        return 0;
    }
    if (status) *status=0;
    return new_parsed_Rexp_from_Msg(msg);
}

/** detached eval (aka detached void eval) initiates eval and detaches the session.
 *  @param cmd command to evaluate. If NULL equivalent to simple detach()
 *  @param status optional status to be reported (zero on success)
 *  @return object describintg he session.
 *          Note that the caller is responsible for freeing the object if not needed. */
Rsession *Rconnection::detachedEval(const char *cmd, int *status) {
    Rmessage *msg = new Rmessage();
    Rmessage *cmdMessage = cmd ? new Rmessage(CMD_detachedVoidEval, cmd) : new Rmessage(CMD_detachSession);
    int res = request(msg, cmdMessage);
    delete cmdMessage;
    if (res) {
	if (status) *status = res;
	delete msg;
	return 0;
    }
    if (msg->pars != 2 ||
	PAR_TYPE(ptoi(msg->par[0][0])) != DT_INT || PAR_LEN(ptoi(msg->par[0][0])) != sizeof(int) ||
	PAR_TYPE(ptoi(msg->par[1][0])) != DT_BYTESTREAM || PAR_LEN(ptoi(msg->par[1][0])) != 32) { // invalid contents
	if (status) *status = -12;
	delete msg;
	return 0;
    }
    Rsession *session = new Rsession(host, ptoi(msg->par[0][1]), (const char*) (msg->par[1] + 1));
    delete msg;
    if (status) *status=0;
    return session;
}

Rsession *Rconnection::detach(int *status) {
    return detachedEval(0, status);
}

int Rconnection::openFile(const char *fn) {
  Rmessage *msg=new Rmessage();
  Rmessage *cmdMessage=new Rmessage(CMD_openFile, fn);
  int res=request(msg,cmdMessage);
  delete (cmdMessage);
  if (!res) res=CMD_STAT(msg->command());
  delete (msg);
  return res;
}

int Rconnection::createFile(const char *fn) {
  Rmessage *msg=new Rmessage();
  Rmessage *cmdMessage=new Rmessage(CMD_createFile, fn);
  int res=request(msg,cmdMessage);
  delete (cmdMessage);
  if (!res) res=CMD_STAT(msg->command());
  delete (msg);
  return res;
}

int Rconnection::readFile(char *buf, unsigned int len) {
  Rmessage *msg=new Rmessage();
  Rmessage *cmdMessage=new Rmessage(CMD_readFile, len);
  int res=request(msg,cmdMessage);
  delete(cmdMessage);
  if (!res) {
    // FIXME: Rserve up to 0.4-0 actually sends buggy response - it ommits DT_BYTESTREAM header!
    if (msg->len > len) {
      // we're in trouble here - techincally we should not get this
      delete(msg);
      return CERR_malformed_packet;
    }
    if (msg->len > 0) memcpy(buf, msg->data, msg->len);
    int rl = msg->len;
    delete(msg);
    return rl;
  }
  delete(msg);
  return CERR_io_error;
}

int Rconnection::writeFile(const char *buf, unsigned int len) {
  Rmessage *msg=new Rmessage();
  Rmessage *cmdMessage=new Rmessage(CMD_writeFile, buf, len);
  int res=request(msg,cmdMessage);
  delete(cmdMessage);
  if (!res && msg->command()==RESP_OK) {
    delete(msg);
    return 0;
  }
  delete(msg);
  // FIXME: this is not really true ...
  return (res==0)?CERR_io_error:res;
}  

int Rconnection::closeFile() {
  Rmessage *msg=new Rmessage();
  Rmessage *cmdMessage=new Rmessage(CMD_closeFile);
  int res=request(msg,cmdMessage);
  delete(cmdMessage);
  if (!res && msg->command()==RESP_OK) {
    delete(msg);
    return 0;
  }
  delete(msg);
  // FIXME: this is not really true ...
  return (res==0)?CERR_io_error:res;
}

int Rconnection::removeFile(const char *fn) {
  Rmessage *msg=new Rmessage();
  Rmessage *cmdMessage=new Rmessage(CMD_removeFile, fn);
  int res=request(msg,cmdMessage);
  delete (cmdMessage);
  if (!res) res=CMD_STAT(msg->command());
  delete (msg);
  return res;  
}

int Rconnection::login(const char *user, const char *pwd) {
  char *authbuf, *c;
  if (!(auth&A_required)) return 0;
  authbuf=(char*) malloc(strlen(user)+strlen(pwd)+22);
  strcpy(authbuf, user); c=authbuf+strlen(user);
  *c='\n'; c++;
  strcpy(c,pwd);
#ifdef unix
  if (auth&A_crypt)
    strcpy(c,crypt(pwd,salt));
#else
  if (!(auth&A_plain)) {
    free(authbuf);
    return CERR_auth_unsupported;
  }
#endif

  Rmessage *msg=new Rmessage();
  Rmessage *cmdMessage=new Rmessage(CMD_login, authbuf);
  int res=request(msg,cmdMessage);
  delete (cmdMessage);
  if (!res) res=CMD_STAT(msg->command());
  delete (msg);
  free(authbuf);
  return res;
}

#ifdef CMD_ctrl

/* server control methods */
int serverEval(const char *cmd);
int serverSource(const char *fn);
int serverShutdown();

int Rconnection::serverEval(const char *cmd) {
    Rmessage *msg = new Rmessage(); /* result message */
    Rmessage *cmdMessage = new Rmessage(CMD_ctrlEval, cmd); /* request message */
    int res = request(msg, cmdMessage);
    delete (cmdMessage);
    if (!res) res = CMD_STAT(msg->command());
    delete (msg);
    return res;
}

int Rconnection::serverSource(const char *fn) {
    Rmessage *msg = new Rmessage(); /* result message */
    Rmessage *cmdMessage = new Rmessage(CMD_ctrlSource, fn); /* request message */
    int res = request(msg, cmdMessage);
    delete (cmdMessage);
    if (!res) res = CMD_STAT(msg->command());
    delete (msg);
    return res;
}

int Rconnection::serverShutdown() {
    Rmessage *msg = new Rmessage(); /* result message */
    Rmessage *cmdMessage = new Rmessage(CMD_ctrlShutdown); /* request message */
    int res = request(msg, cmdMessage);
    delete (cmdMessage);
    if (!res) res = CMD_STAT(msg->command());
    delete (msg);
    return res;
}

#endif
