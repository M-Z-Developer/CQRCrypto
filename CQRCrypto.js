/**
 * ==============================================================================
 * CQRCrypto LEVEL 5 (Top Secret - Military Grade) - CORE LIBRARY by MZ-Developer.xmr - Github https://github.com/M-Z-Developer
 * ==============================================================================
 * Security Level: ML-DSA-87 (Signatures) & ML-KEM-1024 (Key Encapsulation)
 * Symmetric: AES-256-GCM
 * KDF: PBKDF2-SHA512 (600,000 Iterations)
 * Status: Air-Gapped Ready | Zero External Dependencies
 * ==============================================================================
 */

// 1. ================= ML-DSA (Dilithium) Level 5 Engine =================
const ML_DSA = (function() {
    function _t(t){if(!Number.isSafeInteger(t)||t<0)throw new Error(`positive integer expected, not ${t}`)}function Ae(t){return t instanceof Uint8Array||t!=null&&typeof t=="object"&&t.constructor.name==="Uint8Array"}function Q(t,...e){if(!Ae(t))throw new Error("Uint8Array expected");if(e.length>0&&!e.includes(t.length))throw new Error(`Uint8Array expected of length ${e}, not of length=${t.length}`)}function Tt(t,e=!0){if(t.destroyed)throw new Error("Hash instance has been destroyed");if(e&&t.finished)throw new Error("Hash#digest() has already been called")}function Wt(t,e){Q(t);let n=e.outputLen;if(t.length<n)throw new Error(`digestInto() expects output buffer of length at least ${n}`)}var ht=BigInt(4294967295),$t=BigInt(32);function me(t,e=!1){return e?{h:Number(t&ht),l:Number(t>>$t&ht)}:{h:Number(t>>$t&ht)|0,l:Number(t&ht)|0}}function Vt(t,e=!1){let n=new Uint32Array(t.length),o=new Uint32Array(t.length);for(let r=0;r<t.length;r++){let{h:f,l:s}=me(t[r],e);[n[r],o[r]]=[f,s]}return[n,o]}var zt=(t,e,n)=>t<<n|e>>>32-n,Zt=(t,e,n)=>e<<n|t>>>32-n,qt=(t,e,n)=>e<<n-32|t>>>64-n,Qt=(t,e,n)=>t<<n-32|e>>>64-n;var yt=typeof globalThis=="object"&&"crypto"in globalThis?globalThis.crypto:void 0;var Jt=t=>new Uint32Array(t.buffer,t.byteOffset,Math.floor(t.byteLength/4));var Bt=new Uint8Array(new Uint32Array([287454020]).buffer)[0]===68,Le=t=>t<<24&4278190080|t<<8&16711680|t>>>8&65280|t>>>24&255;function Et(t){for(let e=0;e<t.length;e++)t[e]=Le(t[e])}function ke(t){if(typeof t!="string")throw new Error(`utf8ToBytes expected string, got ${typeof t}`);return new Uint8Array(new TextEncoder().encode(t))}function gt(t){return typeof t=="string"&&(t=ke(t)),Q(t),t}var xt=class{clone(){return this._cloneInto()}},Ye={}.toString;function te(t){let e=o=>t().update(gt(o)).digest(),n=t();return e.outputLen=n.outputLen,e.blockLen=n.blockLen,e.create=()=>t(),e}function ee(t){let e=(o,r)=>t(r).update(gt(o)).digest(),n=t({});return e.outputLen=n.outputLen,e.blockLen=n.blockLen,e.create=o=>t(o),e}function ne(t=32){if(yt&&typeof yt.getRandomValues=="function")return yt.getRandomValues(new Uint8Array(t));throw new Error("crypto.getRandomValues must be defined")}var se=[],ce=[],ie=[],_e=BigInt(0),it=BigInt(1),Te=BigInt(2),Be=BigInt(7),Ee=BigInt(256),Oe=BigInt(113);for(let t=0,e=it,n=1,o=0;t<24;t++){[n,o]=[o,(2*n+3*o)%5],se.push(2*(5*o+n)),ce.push((t+1)*(t+2)/2%64);let r=_e;for(let f=0;f<7;f++)e=(e<<it^(e>>Be)*Oe)%Ee,e&Te&&(r^=it<<(it<<BigInt(f))-it);ie.push(r)}var[Se,Me]=Vt(ie,!0),oe=(t,e,n)=>n>32?qt(t,e,n):zt(t,e,n),re=(t,e,n)=>n>32?Qt(t,e,n):Zt(t,e,n);function Ie(t,e=24){let n=new Uint32Array(10);for(let o=24-e;o<24;o++){for(let s=0;s<10;s++)n[s]=t[s]^t[s+10]^t[s+20]^t[s+30]^t[s+40];for(let s=0;s<10;s+=2){let l=(s+8)%10,A=(s+2)%10,_=n[A],B=n[A+1],X=oe(_,B,1)^n[l],z=re(_,B,1)^n[l+1];for(let H=0;H<50;H+=10)t[s+H]^=X,t[s+H+1]^=z}let r=t[2],f=t[3];for(let s=0;s<24;s++){let l=ce[s],A=oe(r,f,l),_=re(r,f,l),B=se[s];r=t[B],f=t[B+1],t[B]=A,t[B+1]=_}for(let s=0;s<50;s+=10){for(let l=0;l<10;l++)n[l]=t[s+l];for(let l=0;l<10;l++)t[s+l]^=~n[(l+2)%10]&n[(l+4)%10]}t[0]^=Se[o],t[1]^=Me[o]}n.fill(0)}var wt=class t extends xt{constructor(e,n,o,r=!1,f=24){if(super(),this.blockLen=e,this.suffix=n,this.outputLen=o,this.enableXOF=r,this.rounds=f,this.pos=0,this.posOut=0,this.finished=!1,this.destroyed=!1,_t(o),0>=this.blockLen||this.blockLen>=200)throw new Error("Sha3 supports only keccak-f1600 function");this.state=new Uint8Array(200),this.state32=Jt(this.state)}keccak(){Bt||Et(this.state32),Ie(this.state32,this.rounds),Bt||Et(this.state32),this.posOut=0,this.pos=0}update(e){Tt(this);let{blockLen:n,state:o}=this;e=gt(e);let r=e.length;for(let f=0;f<r;){let s=Math.min(n-this.pos,r-f);for(let l=0;l<s;l++)o[this.pos++]^=e[f++];this.pos===n&&this.keccak()}return this}finish(){if(this.finished)return;this.finished=!0;let{state:e,suffix:n,pos:o,blockLen:r}=this;e[o]^=n,(n&128)!==0&&o===r-1&&this.keccak(),e[r-1]^=128,this.keccak()}writeInto(e){Tt(this,!1),Q(e),this.finish();let n=this.state,{blockLen:o}=this;for(let r=0,f=e.length;r<f;){this.posOut>=o&&this.keccak();let s=Math.min(o-this.posOut,f-r);e.set(n.subarray(this.posOut,this.posOut+s),r),this.posOut+=s,r+=s}return e}xofInto(e){if(!this.enableXOF)throw new Error("XOF is not possible for this instance");return this.writeInto(e)}xof(e){return _t(e),this.xofInto(new Uint8Array(e))}digestInto(e){if(Wt(e,this),this.finished)throw new Error("digest() was already called");return this.writeInto(e),this.destroy(),e}digest(){return this.digestInto(new Uint8Array(this.outputLen))}destroy(){this.destroyed=!0,this.state.fill(0)}_cloneInto(e){let{blockLen:n,suffix:o,outputLen:r,rounds:f,enableXOF:s}=this;return e||(e=new t(n,o,r,s,f)),e.state32.set(this.state32),e.pos=this.pos,e.posOut=this.posOut,e.finished=this.finished,e.rounds=f,e.suffix=o,e.outputLen=r,e.enableXOF=s,e.destroyed=this.destroyed,e}},$=(t,e,n)=>te(()=>new wt(e,t,n)),$e=$(6,144,224/8),Ve=$(6,136,256/8),ze=$(6,104,384/8),Ze=$(6,72,512/8),qe=$(1,144,224/8),Qe=$(1,136,256/8),Je=$(1,104,384/8),tn=$(1,72,512/8),fe=(t,e,n)=>ee((o={})=>new wt(e,t,o.dkLen===void 0?n:o.dkLen,!0)),le=fe(31,168,128/8),C=fe(31,136,256/8);var ot=Q,ue=ne;function de(t,e){if(t.length!==e.length)return!1;let n=0;for(let o=0;o<t.length;o++)n|=t[o]^e[o];return n===0}function ft(...t){let e=o=>typeof o=="number"?o:o.bytesLen,n=t.reduce((o,r)=>o+e(r),0);return{bytesLen:n,encode:o=>{let r=new Uint8Array(n);for(let f=0,s=0;f<t.length;f++){let l=t[f],A=e(l),_=typeof l=="number"?o[f]:l.encode(o[f]);ot(_,A),r.set(_,s),typeof l!="number"&&_.fill(0),s+=A}return r},decode:o=>{ot(o,n);let r=[];for(let f of t){let s=e(f),l=o.subarray(0,s);r.push(typeof f=="number"?l:f.decode(l)),o=o.subarray(s)}return r}}}function J(t,e){let n=e*t.bytesLen;return{bytesLen:n,encode:o=>{if(o.length!==e)throw new Error(`vecCoder.encode: wrong length=${o.length}. Expected: ${e}`);let r=new Uint8Array(n);for(let f=0,s=0;f<o.length;f++){let l=t.encode(o[f]);r.set(l,s),l.fill(0),s+=l.length}return r},decode:o=>{ot(o,n);let r=[];for(let f=0;f<o.length;f+=t.bytesLen)r.push(t.decode(o.subarray(f,f+t.bytesLen)));return r}}}function Ot(...t){for(let e of t)if(Array.isArray(e))for(let n of e)n.fill(0);else e.fill(0)}function St(t){return(1<<t)-1}function Ue(t,e=8){let r=t.toString(2).padStart(8,"0").slice(-e).padStart(7,"0").split("").reverse().join("");return Number.parseInt(r,2)}var ae=t=>{let{newPoly:e,N:n,o:o,F:r,ROOT_OF_UNITY:f,brvBits:s,isKyber:l}=t,A=(p,w=o)=>{let y=p%w|0;return(y>=0?y|0:w+y|0)|0},_=(p,w=o)=>{let y=A(p,w)|0;return(y>w>>1?y-w|0:y)|0};function B(){let p=e(n);for(let w=0;w<n;w++){let y=Ue(w,s),T=BigInt(f)**BigInt(y)%BigInt(o);p[w]=Number(T)|0}return p}let X=B(),z=l?128:n,H=l?1:0;return{mod:A,smod:_,nttZetas:X,NTT:{encode:p=>{for(let w=1,y=128;y>H;y>>=1)for(let T=0;T<n;T+=2*y){let N=X[w++];for(let m=T;m<T+y;m++){let E=A(N*p[m+y]);p[m+y]=A(p[m]-E)|0,p[m]=A(p[m]+E)|0}}return p},decode:p=>{for(let w=z-1,y=1+H;y<z+H;y<<=1)for(let T=0;T<n;T+=2*y){let N=X[w--];for(let m=T;m<T+y;m++){let E=p[m];p[m]=A(E+p[m+y]),p[m+y]=A(N*(p[m+y]-E))}}for(let w=0;w<p.length;w++)p[w]=A(r*p[w]);return p}},bitsCoder:(p,w)=>{let y=St(p),T=p*(n/8);return{bytesLen:T,encode:N=>{let m=new Uint8Array(T);for(let E=0,Y=0,M=0,st=0;E<N.length;E++)for(Y|=(w.encode(N[E])&y)<<M,M+=p;M>=8;M-=8,Y>>=8)m[st++]=Y&St(M);return m},decode:N=>{let m=e(n);for(let E=0,Y=0,M=0,st=0;E<N.length;E++)for(Y|=N[E]<<M,M+=8;M>=p;M-=p,Y>>=p)m[st++]=w.decode(Y&y);return m}}}}},pe=t=>(e,n)=>{n||(n=t.blockLen);let o=new Uint8Array(e.length+2);o.set(e);let r=e.length,f=new Uint8Array(n),s=t.create({}),l=0,A=0;return{stats:()=>({calls:l,xofs:A}),get:(_,B)=>(o[r+0]=_,o[r+1]=B,s.destroy(),s=t.create({}).update(o),l++,()=>(A++,s.xofInto(f))),clean:()=>{s.destroy(),f.fill(0),o.fill(0)}}},bt=pe(le),At=pe(C);var L=256,V=8380417,Ce=1753,He=8347681,nt=13,It=Math.floor((V-1)/88)|0,Ut=Math.floor((V-1)/32)|0,Ct={2:{K:4,L:4,D:nt,GAMMA1:2**17,GAMMA2:It,TAU:39,ETA:2,OMEGA:80},3:{K:6,L:5,D:nt,GAMMA1:2**19,GAMMA2:Ut,TAU:49,ETA:4,OMEGA:55},5:{K:8,L:7,D:nt,GAMMA1:2**19,GAMMA2:Ut,TAU:60,ETA:2,OMEGA:75}},F=t=>new Int32Array(t),{mod:et,smod:mt,NTT:S,bitsCoder:je}=ae({N:L,o:V,F:He,ROOT_OF_UNITY:Ce,newPoly:F,isKyber:!1,brvBits:8}),lt=(t,e)=>je(t,{encode:n=>e?e(n):n,decode:n=>e?e(n):n}),rt=(t,e)=>{for(let n=0;n<t.length;n++)t[n]=et(t[n]+e[n]);return t},he=(t,e)=>{for(let n=0;n<t.length;n++)t[n]=et(t[n]-e[n]);return t},Re=t=>{for(let e=0;e<L;e++)t[e]<<=nt;return t},ut=(t,e)=>{for(let n=0;n<L;n++)if(Math.abs(mt(t[n]))>=e)return!0;return!1},tt=(t,e)=>{let n=F(L);for(let o=0;o<t.length;o++)n[o]=et(t[o]*e[o]);return n};function Mt(t){let e=F(L);for(let n=0;n<L;){let o=t();if(o.length%3)throw new Error("RejNTTPoly: unaligned block");for(let r=0;n<L&&r<=o.length-3;r+=3){let f=(o[r+0]|o[r+1]<<8|o[r+2]<<16)&8388607;f<V&&(e[n++]=f)}}return e}function Ht(t){let{K:e,L:n,GAMMA1:o,GAMMA2:r,TAU:f,ETA:s,OMEGA:l}=t,{CRH_BYTES:A,TR_BYTES:_,C_TILDE_BYTES:B,XOF128:X,XOF256:z}=t;if(![2,4].includes(s))throw new Error("Wrong ETA");if(![1<<17,1<<19].includes(o))throw new Error("Wrong GAMMA1");if(![It,Ut].includes(r))throw new Error("Wrong GAMMA2");let H=f*s,dt=c=>{let u=et(c),i=mt(u,2*r)|0;return u-i===V-1?{r1:0,r0:i-1|0}:{r1:Math.floor((u-i)/(2*r))|0,r0:i}},jt=c=>dt(c).r1,p=c=>dt(c).r0,w=(c,u)=>c<=r||c>V-r||c===V-r&&u===0?0:1,y=(c,u)=>{let i=Math.floor((V-1)/(2*r)),{r1:d,r0:h}=dt(u);return c===1?h>0?et(d+1,i)|0:et(d-1,i)|0:d|0},T=c=>{let u=et(c),i=mt(u,2**nt)|0;return{r1:Math.floor((u-i)/2**nt)|0,r0:i}},N={bytesLen:l+e,encode:c=>{if(c===!1)throw new Error("hint.encode: hint is false");let u=new Uint8Array(l+e);for(let i=0,d=0;i<e;i++){for(let h=0;h<L;h++)c[i][h]!==0&&(u[d++]=h);u[l+i]=d}return u},decode:c=>{let u=[],i=0;for(let d=0;d<e;d++){let h=F(L);if(c[l+d]<i||c[l+d]>l)return!1;for(let x=i;x<c[l+d];x++){if(x>i&&c[x]<=c[x-1])return!1;h[c[x]]=1}i=c[l+d],u.push(h)}for(let d=i;d<l;d++)if(c[d]!==0)return!1;return u}},m=lt(s===2?3:4,c=>s-c),E=lt(13,c=>(1<<nt-1)-c),Y=lt(10),M=lt(o===1<<17?18:20,c=>mt(o-c)),st=lt(r===It?6:4),Rt=J(st,e),Ft=ft(32,J(Y,e)),Nt=ft(32,32,_,J(m,n),J(m,e),J(E,e)),Lt=ft(B,J(M,n),N),Gt=s===2?c=>c<15?2-c%5:!1:c=>c<9?4-c:!1;function Pt(c){let u=F(L);for(let i=0;i<L;){let d=c();for(let h=0;i<L&&h<d.length;h+=1){let x=Gt(d[h]&15),k=Gt(d[h]>>4&15);x!==!1&&(u[i++]=x),i<L&&k!==!1&&(u[i++]=k)}}return u}let Xt=c=>{let u=F(L),i=C.create({}).update(c),d=new Uint8Array(C.blockLen);i.xofInto(d);let h=d.slice(0,8);for(let x=L-f,k=8,O=0,I=0;x<L;x++){let U=x+1;for(;U>x;)U=d[k++],!(k<C.blockLen)&&(i.xofInto(d),k=0);u[x]=u[U],u[U]=1-((h[O]>>I++&1)<<1),I>=8&&(O++,I=0)}return u},ye=c=>{let u=F(L),i=F(L);for(let d=0;d<c.length;d++){let{r0:h,r1:x}=T(c[d]);u[d]=h,i[d]=x}return{r0:u,r1:i}},xe=(c,u)=>{for(let i=0;i<L;i++)c[i]=y(u[i],c[i]);return c},ge=(c,u)=>{let i=F(L),d=0;for(let h=0;h<L;h++){let x=w(c[h],u[h]);i[h]=x,d+=x}return{v:i,cnt:d}},we=32,Yt=ft(32,64,32);return{signRandBytes:we,keygen:(c=ue(32))=>{let u=new Uint8Array(34);u.set(c),u[32]=e,u[33]=n;let[i,d,h]=Yt.decode(C(u,{dkLen:Yt.bytesLen})),x=z(d),k=[];for(let g=0;g<n;g++)k.push(Pt(x.get(g&255,g>>8&255)));let O=[];for(let g=n;g<n+e;g++)O.push(Pt(x.get(g&255,g>>8&255)));let I=k.map(g=>S.encode(g.slice())),U=[],K=[],v=X(i),G=F(L);for(let g=0;g<e;g++){G.fill(0);for(let R=0;R<n;R++){let q=Mt(v.get(R,g));rt(G,tt(q,I[R]))}S.decode(G);let{r0:j,r1:P}=ye(rt(G,O[g]));U.push(j),K.push(P)}let D=Ft.encode([i,K]),Z=C(D,{dkLen:_}),a=Nt.encode([i,h,Z,k,O,U]);return v.clean(),x.clean(),Ot(i,d,h,k,O,I,G,U,K,Z,u),{publicKey:D,secretKey:a}},sign:(c,u,i)=>{let[d,h,x,k,O,I]=Nt.decode(c),U=[],K=X(d);for(let a=0;a<e;a++){let g=[];for(let j=0;j<n;j++)g.push(Mt(K.get(j,a)));U.push(g)}K.clean();for(let a=0;a<n;a++)S.encode(k[a]);for(let a=0;a<e;a++)S.encode(O[a]),S.encode(I[a]);let v=C.create({dkLen:A}).update(x).update(u).digest(),G=i||new Uint8Array(32);ot(G);let D=C.create({dkLen:A}).update(h).update(G).update(v).digest();ot(D,A);let Z=z(D,M.bytesLen);t:for(let a=0;;){let g=[];for(let b=0;b<n;b++,a++)g.push(M.decode(Z.get(a&255,a>>8)()));let j=g.map(b=>S.encode(b.slice())),P=[];for(let b=0;b<e;b++){let ct=F(L);for(let W=0;W<n;W++)rt(ct,tt(U[b][W],j[W]));S.decode(ct),P.push(ct)}let R=P.map(b=>b.map(jt)),q=C.create({dkLen:B}).update(v).update(Rt.encode(R)).digest(),at=S.encode(Xt(q)),pt=k.map(b=>tt(b,at));for(let b=0;b<n;b++)if(rt(S.decode(pt[b]),g[b]),ut(pt[b],o-H))continue t;let vt=0,kt=[];for(let b=0;b<e;b++){let ct=S.decode(tt(O[b],at)),W=he(P[b],ct).map(p);if(ut(W,r-H))continue t;let Dt=S.decode(tt(I[b],at));if(ut(Dt,r))continue t;rt(W,Dt);let Kt=ge(W,R[b]);kt.push(Kt.v),vt+=Kt.cnt}if(vt>l)continue;Z.clean();let be=Lt.encode([q,pt,kt]);return Ot(q,pt,kt,at,R,P,j,g,D,v,k,O,I,...U),be}throw new Error("Unreachable code path reached, report this error")},verify:(c,u,i)=>{let[d,h]=Ft.decode(c),x=C(c,{dkLen:_});if(i.length!==Lt.bytesLen)return!1;let[k,O,I]=Lt.decode(i);if(I===!1)return!1;for(let a=0;a<n;a++)if(ut(O[a],o-H))return!1;let U=C.create({dkLen:A}).update(x).update(u).digest(),K=S.encode(Xt(k)),v=O.map(a=>a.slice());for(let a=0;a<n;a++)S.encode(v[a]);let G=[],D=X(d);for(let a=0;a<e;a++){let g=tt(S.encode(Re(h[a])),K),j=F(L);for(let R=0;R<n;R++){let q=Mt(D.get(R,a));rt(j,tt(q,v[R]))}let P=S.decode(he(j,g));G.push(xe(P,I[a]))}D.clean();let Z=C.create({dkLen:B}).update(U).update(Rt.encode(G)).digest();for(let a of I)if(!(a.reduce((j,P)=>j+P,0)<=l))return!1;for(let a of O)if(ut(a,o-H))return!1;return de(k,Z)}}}
    const hn = Ht({...Ct[5],CRH_BYTES:64,TR_BYTES:64,C_TILDE_BYTES:64,XOF128:bt,XOF256:At});
    return { ml_dsa87: hn };
})();

// 2. ================= ML-KEM (Kyber) Level 5 Engine =================
const ML_KEM = (function() {
    function J(t){if(!Number.isSafeInteger(t)||t<0)throw new Error(`positive integer expected, not ${t}`)}function It(t){return t instanceof Uint8Array||t!=null&&typeof t=="object"&&t.constructor.name==="Uint8Array"}function I(t,...e){if(!It(t))throw new Error("Uint8Array expected");if(e.length>0&&!e.includes(t.length))throw new Error(`Uint8Array expected of length ${e}, not of length=${t.length}`)}function tt(t,e=!0){if(t.destroyed)throw new Error("Hash instance has been destroyed");if(e&&t.finished)throw new Error("Hash#digest() has already been called")}function ft(t,e){I(t);let n=e.outputLen;if(t.length<n)throw new Error(`digestInto() expects output buffer of length at least ${n}`)}var $=BigInt(4294967295),lt=BigInt(32);function Kt(t,e=!1){return e?{h:Number(t&$),l:Number(t>>lt&$)}:{h:Number(t>>lt&$)|0,l:Number(t&$)|0}}function at(t,e=!1){let n=new Uint32Array(t.length),o=new Uint32Array(t.length);for(let r=0;r<t.length;r++){let{h:c,l:s}=Kt(t[r],e);[n[r],o[r]]=[c,s]}return[n,o]}var pt=(t,e,n)=>t<<n|e>>>32-n,dt=(t,e,n)=>e<<n|t>>>32-n,ht=(t,e,n)=>e<<n-32|t>>>64-n,yt=(t,e,n)=>t<<n-32|e>>>64-n;var D=typeof globalThis=="object"&&"crypto"in globalThis?globalThis.crypto:void 0;var z=t=>new Uint32Array(t.buffer,t.byteOffset,Math.floor(t.byteLength/4));var et=new Uint8Array(new Uint32Array([287454020]).buffer)[0]===68,Ct=t=>t<<24&4278190080|t<<8&16711680|t>>>8&65280|t>>>24&255;function nt(t){for(let e=0;e<t.length;e++)t[e]=Ct(t[e])}function Ft(t){if(typeof t!="string")throw new Error(`utf8ToBytes expected string, got ${typeof t}`);return new Uint8Array(new TextEncoder().encode(t))}function G(t){return typeof t=="string"&&(t=Ft(t)),I(t),t}var V=class{clone(){return this._cloneInto()}},ce={}.toString;function bt(t){let e=o=>t().update(G(o)).digest(),n=t();return e.outputLen=n.outputLen,e.blockLen=n.blockLen,e.create=()=>t(),e}function xt(t){let e=(o,r)=>t(r).update(G(o)).digest(),n=t({});return e.outputLen=n.outputLen,e.blockLen=n.blockLen,e.create=o=>t(o),e}function gt(t=32){if(D&&typeof D.getRandomValues=="function")return D.getRandomValues(new Uint8Array(t));throw new Error("crypto.getRandomValues must be defined")}var Lt=[],At=[],kt=[],Nt=BigInt(0),N=BigInt(1),jt=BigInt(2),Rt=BigInt(7),vt=BigInt(256),Xt=BigInt(113);for(let t=0,e=N,n=1,o=0;t<24;t++){[n,o]=[o,(2*n+3*o)%5],Lt.push(2*(5*o+n)),At.push((t+1)*(t+2)/2%64);let r=Nt;for(let c=0;c<7;c++)e=(e<<N^(e>>Rt)*Xt)%vt,e&jt&&(r^=N<<(N<<BigInt(c))-N);kt.push(r)}var[Pt,Mt]=at(kt,!0),wt=(t,e,n)=>n>32?ht(t,e,n):pt(t,e,n),mt=(t,e,n)=>n>32?yt(t,e,n):dt(t,e,n);function $t(t,e=24){let n=new Uint32Array(10);for(let o=24-e;o<24;o++){for(let s=0;s<10;s++)n[s]=t[s]^t[s+10]^t[s+20]^t[s+30]^t[s+40];for(let s=0;s<10;s+=2){let i=(s+8)%10,p=(s+2)%10,m=n[p],x=n[p+1],y=wt(m,x,1)^n[i],g=mt(m,x,1)^n[i+1];for(let b=0;b<50;b+=10)t[s+b]^=y,t[s+b+1]^=g}let r=t[2],c=t[3];for(let s=0;s<24;s++){let i=At[s],p=wt(r,c,i),m=mt(r,c,i),x=Lt[s];r=t[x],c=t[x+1],t[x]=p,t[x+1]=m}for(let s=0;s<50;s+=10){for(let i=0;i<10;i++)n[i]=t[s+i];for(let i=0;i<10;i++)t[s+i]^=~n[(i+2)%10]&n[(i+4)%10]}t[0]^=Pt[o],t[1]^=Mt[o]}n.fill(0)}var W=class t extends V{constructor(e,n,o,r=!1,c=24){if(super(),this.blockLen=e,this.suffix=n,this.outputLen=o,this.enableXOF=r,this.rounds=c,this.pos=0,this.posOut=0,this.finished=!1,this.destroyed=!1,J(o),0>=this.blockLen||this.blockLen>=200)throw new Error("Sha3 supports only keccak-f1600 function");this.state=new Uint8Array(200),this.state32=z(this.state)}keccak(){et||nt(this.state32),$t(this.state32,this.rounds),et||nt(this.state32),this.posOut=0,this.pos=0}update(e){tt(this);let{blockLen:n,state:o}=this;e=G(e);let r=e.length;for(let c=0;c<r;){let s=Math.min(n-this.pos,r-c);for(let i=0;i<s;i++)o[this.pos++]^=e[c++];this.pos===n&&this.keccak()}return this}finish(){if(this.finished)return;this.finished=!0;let{state:e,suffix:n,pos:o,blockLen:r}=this;e[o]^=n,(n&128)!==0&&o===r-1&&this.keccak(),e[r-1]^=128,this.keccak()}writeInto(e){tt(this,!1),I(e),this.finish();let n=this.state,{blockLen:o}=this;for(let r=0,c=e.length;r<c;){this.posOut>=o&&this.keccak();let s=Math.min(o-this.posOut,c-r);e.set(n.subarray(this.posOut,this.posOut+s),r),this.posOut+=s,r+=s}return e}xofInto(e){if(!this.enableXOF)throw new Error("XOF is not possible for this instance");return this.writeInto(e)}xof(e){return J(e),this.xofInto(new Uint8Array(e))}digestInto(e){if(ft(e,this),this.finished)throw new Error("digest() was already called");return this.writeInto(e),this.destroy(),e}digest(){return this.digestInto(new Uint8Array(this.outputLen))}destroy(){this.destroyed=!0,this.state.fill(0)}_cloneInto(e){let{blockLen:n,suffix:o,outputLen:r,rounds:c,enableXOF:s}=this;return e||(e=new t(n,o,r,s,c)),e.state32.set(this.state32),e.pos=this.pos,e.posOut=this.posOut,e.finished=this.finished,e.rounds=c,e.suffix=o,e.outputLen=r,e.enableXOF=s,e.destroyed=this.destroyed,e}},S=(t,e,n)=>bt(()=>new W(e,t,n)),ae=S(6,144,224/8),_t=S(6,136,256/8),pe=S(6,104,384/8),Bt=S(6,72,512/8),de=S(1,144,224/8),he=S(1,136,256/8),ye=S(1,104,384/8),be=S(1,72,512/8),Tt=(t,e,n)=>xt((o={})=>new W(e,t,o.dkLen===void 0?n:o.dkLen,!0)),Ot=Tt(31,168,128/8),Z=Tt(31,136,256/8);var E=I,ot=gt;function rt(t,e){if(t.length!==e.length)return!1;let n=0;for(let o=0;o<t.length;o++)n|=t[o]^e[o];return n===0}function j(...t){let e=o=>typeof o=="number"?o:o.bytesLen,n=t.reduce((o,r)=>o+e(r),0);return{bytesLen:n,encode:o=>{let r=new Uint8Array(n);for(let c=0,s=0;c<t.length;c++){let i=t[c],p=e(i),m=typeof i=="number"?o[c]:i.encode(o[c]);E(m,p),r.set(m,s),typeof i!="number"&&m.fill(0),s+=p}return r},decode:o=>{E(o,n);let r=[];for(let c of t){let s=e(c),i=o.subarray(0,s);r.push(typeof c=="number"?i:c.decode(i)),o=o.subarray(s)}return r}}}function q(t,e){let n=e*t.bytesLen;return{bytesLen:n,encode:o=>{if(o.length!==e)throw new Error(`vecCoder.encode: wrong length=${o.length}. Expected: ${e}`);let r=new Uint8Array(n);for(let c=0,s=0;c<o.length;c++){let i=t.encode(o[c]);r.set(i,s),i.fill(0),s+=i.length}return r},decode:o=>{E(o,n);let r=[];for(let c=0;c<o.length;c+=t.bytesLen)r.push(t.decode(o.subarray(c,c+t.bytesLen)));return r}}}function U(...t){for(let e of t)if(Array.isArray(e))for(let n of e)n.fill(0);else e.fill(0)}function st(t){return(1<<t)-1}function Dt(t,e=8){let r=t.toString(2).padStart(8,"0").slice(-e).padStart(7,"0").split("").reverse().join("");return Number.parseInt(r,2)}var Et=t=>{let{newPoly:e,N:n,Q:o,F:r,ROOT_OF_UNITY:c,brvBits:s,isKyber:i}=t,p=(u,a=o)=>{let f=u%a|0;return(f>=0?f|0:a+f|0)|0},m=(u,a=o)=>{let f=p(u,a)|0;return(f>a>>1?f-a|0:f)|0};function x(){let u=e(n);for(let a=0;a<n;a++){let f=Dt(a,s),h=BigInt(c)**BigInt(f)%BigInt(o);u[a]=Number(h)|0}return u}let y=x(),g=i?128:n,b=i?1:0;return{mod:p,smod:m,nttZetas:y,NTT:{encode:u=>{for(let a=1,f=128;f>b;f>>=1)for(let h=0;h<n;h+=2*f){let w=y[a++];for(let l=h;l<h+f;l++){let d=p(w*u[l+f]);u[l+f]=p(u[l]-d)|0,u[l]=p(u[l]+d)|0}}return u},decode:u=>{for(let a=g-1,f=1+b;f<g+b;f<<=1)for(let h=0;h<n;h+=2*f){let w=y[a--];for(let l=h;l<h+f;l++){let d=u[l];u[l]=p(d+u[l+f]),u[l+f]=p(w*(u[l+f]-d))}}for(let a=0;a<u.length;a++)u[a]=p(r*u[a]);return u}},bitsCoder:(u,a)=>{let f=st(u),h=u*(n/8);return{bytesLen:h,encode:w=>{let l=new Uint8Array(h);for(let d=0,B=0,k=0,L=0;d<w.length;d++)for(B|=(a.encode(w[d])&f)<<k,k+=u;k>=8;k-=8,B>>=8)l[L++]=B&st(k);return l},decode:w=>{let l=e(n);for(let d=0,B=0,k=0,L=0;d<w.length;d++)for(B|=w[d]<<k,k+=8;k>=u;k-=u,B>>=u)l[L++]=a.decode(B&f);return l}}}}},Vt=t=>(e,n)=>{n||(n=t.blockLen);let o=new Uint8Array(e.length+2);o.set(e);let r=e.length,c=new Uint8Array(n),s=t.create({}),i=0,p=0;return{stats:()=>({calls:i,xofs:p}),get:(m,x)=>(o[r+0]=m,o[r+1]=x,s.destroy(),s=t.create({}).update(o),i++,()=>(p++,s.xofInto(c))),clean:()=>{s.destroy(),c.fill(0),o.fill(0)}}},Ht=Vt(Ot);var A=256,H=3329,zt=3303,Gt=17,{mod:X,nttZetas:Wt,NTT:K,bitsCoder:Zt}=Et({N:A,Q:H,F:zt,ROOT_OF_UNITY:Gt,newPoly:t=>new Uint16Array(t),brvBits:7,isKyber:!0}),ct={512:{N:A,Q:H,K:2,ETA1:3,ETA2:2,du:10,dv:4,RBGstrength:128},768:{N:A,Q:H,K:3,ETA1:2,ETA2:2,du:10,dv:4,RBGstrength:192},1024:{N:A,Q:H,K:4,ETA1:2,ETA2:2,du:11,dv:5,RBGstrength:256}},qt=t=>{if(t>=12)return{encode:n=>n,decode:n=>n};let e=2**(t-1);return{encode:n=>((n<<t)+H/2)/H,decode:n=>n*H+e>>>t}},R=t=>Zt(t,qt(t));function C(t,e){for(let n=0;n<A;n++)t[n]=X(t[n]+e[n])}function Qt(t,e){for(let n=0;n<A;n++)t[n]=X(t[n]-e[n])}function Yt(t,e,n,o,r){let c=X(e*o*r+t*n),s=X(t*o+e*n);return{c0:c,c1:s}}function Q(t,e){for(let n=0;n<A/2;n++){let o=Wt[64+(n>>1)];n&1&&(o=-o);let{c0:r,c1:c}=Yt(t[2*n+0],t[2*n+1],e[2*n+0],e[2*n+1],o);t[2*n+0]=r;t[2*n+1]=c}return t}function St(t){let e=new Uint16Array(A);for(let n=0;n<A;){let o=t();if(o.length%3)throw new Error("SampleNTT: unaligned block");for(let r=0;n<A&&r+3<=o.length;r+=3){let c=(o[r+0]>>0|o[r+1]<<8)&4095,s=(o[r+1]>>4|o[r+2]<<4)&4095;c<H&&(e[n++]=c),n<A&&s<H&&(e[n++]=s)}}return e}function v(t,e,n,o){let r=t(o*A/4,e,n),c=new Uint16Array(A),s=z(r),i=0;for(let p=0,m=0,x=0,y=0;p<s.length;p++){let g=s[p];for(let b=0;b<32;b++)x+=g&1,g>>=1,i+=1,i===o?(y=x,x=0):i===2*o&&(c[m++]=X(y-x),x=0,i=0)}if(i)throw new Error(`sampleCBD: leftover bits: ${i}`);return c}var Jt=t=>{let{K:e,PRF:n,XOF:o,HASH512:r,ETA1:c,ETA2:s,du:i,dv:p}=t,m=R(1),x=R(p),y=R(i),g=j(q(R(12),e),32),b=q(R(12),e),T=j(q(y,e),x),O=j(32,32);return{secretCoder:b,secretKeyLen:b.bytesLen,publicKeyLen:g.bytesLen,cipherTextLen:T.bytesLen,keygen:u=>{let a=new Uint8Array(33);a.set(u),a[32]=e;let f=r(a),[h,w]=O.decode(f),l=[],d=[];for(let L=0;L<e;L++)l.push(K.encode(v(n,w,L,c)));let B=o(h);for(let L=0;L<e;L++){let F=K.encode(v(n,w,e+L,c));for(let _=0;_<e;_++){let P=St(B.get(_,L));C(F,Q(P,l[_]))}d.push(F)}B.clean();let k={publicKey:g.encode([d,h]),secretKey:b.encode(l)};return U(h,w,l,d,a,f),k},encrypt:(u,a,f)=>{let[h,w]=g.decode(u),l=[];for(let _=0;_<e;_++)l.push(K.encode(v(n,f,_,c)));let d=o(w),B=new Uint16Array(A),k=[];for(let _=0;_<e;_++){let P=v(n,f,e+_,s),Y=new Uint16Array(A);for(let M=0;M<e;M++){let Ut=St(d.get(_,M));C(Y,Q(Ut,l[M]))}C(P,K.decode(Y)),k.push(P),C(B,Q(h[_],l[_])),Y.fill(0)}d.clean();let L=v(n,f,2*e,s);C(L,K.decode(B));let F=m.decode(a);return C(F,L),U(h,l,B,L),T.encode([k,F])},decrypt:(u,a)=>{let[f,h]=T.decode(u),w=b.decode(a),l=new Uint16Array(A);for(let d=0;d<e;d++)C(l,Q(w[d],K.encode(f[d])));return Qt(h,K.decode(l)),U(l,w,f),m.encode(h)}}};function it(t){let e=Jt(t),{HASH256:n,HASH512:o,KDF:r}=t,{secretCoder:c,cipherTextLen:s}=e,i=e.publicKeyLen,p=j(e.secretKeyLen,e.publicKeyLen,32,32),m=p.bytesLen,x=32;return{publicKeyLen:i,msgLen:x,keygen:(y=ot(64))=>{E(y,64);let{publicKey:g,secretKey:b}=e.keygen(y.subarray(0,32)),T=n(g),O=p.encode([b,g,T,y.subarray(32)]);return U(b,T),{publicKey:g,secretKey:O}},encapsulate:(y,g=ot(32))=>{E(y,i),E(g,x);let b=y.subarray(0,384*t.K),T=c.encode(c.decode(b.slice()));if(!rt(T,b))throw U(T),new Error("ML-KEM.encapsulate: wrong publicKey modulus");U(T);let O=o.create().update(g).update(n(y)).digest(),u=e.encrypt(y,g,O.subarray(32,64));return O.subarray(32).fill(0),{cipherText:u,sharedSecret:O.subarray(0,32)}},decapsulate:(y,g)=>{E(g,m),E(y,s);let[b,T,O,u]=p.decode(g),a=e.decrypt(y,b),f=o.create().update(a).update(O).digest(),h=f.subarray(0,32),w=e.encrypt(T,a,f.subarray(32,64)),l=rt(y,w),d=r.create({dkLen:32}).update(u).update(y).digest();return U(a,w,l?d:h),l?h:d}}}function te(t,e,n){return Z.create({dkLen:t}).update(e).update(new Uint8Array([n])).digest()}var ut={HASH256:_t,HASH512:Bt,KDF:Z,XOF:Ht,PRF:te},Se=it({...ut,...ct[1024]});
    return { ml_kem1024: Se };
})();

// 3. ================= CQR-Crypto Level 5 Wrapper =================

/**
 * CQR Crypto Main Library
 * Zero Dependency | Node.js & Browser Support (via crypto.subtle)
 */
class CQRCrypto {
    constructor() {
        this.DEVELOPER_ID = "mz-developer.xmr";
        this.SYSTEM_ID = "CQR-Crypto";
        this.CQR_VERSION = 2; // Level 5 Version Flag
        
        // Expose underlying engines locally for this class
        this.dsa = ML_DSA.ml_dsa87;
        this.kem = ML_KEM.ml_kem1024;
    }

    // --- Utility Methods ---

    /**
     * @param {Uint8Array} bytes 
     * @returns {string} base64url string
     */
    bytesToBase64url(bytes) {
        let bin = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    /**
     * @param {string} b64 base64url string
     * @returns {Uint8Array}
     */
    base64urlToBytes(b64) {
        b64 = b64.trim().replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        const bin = atob(b64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            arr[i] = bin.charCodeAt(i);
        }
        return arr;
    }

    /**
     * @param {any} obj 
     * @returns {any} Canonicalized JSON Object
     */
    canonicalize(obj) {
        if (obj === null || typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.map(x => this.canonicalize(x));
        return Object.keys(obj).sort().reduce((acc, key) => ({ ...acc, [key]: this.canonicalize(obj[key]) }), {});
    }

    /**
     * Packs DSA and KEM keys into a single binary buffer
     * @param {Uint8Array} dsaKeyBytes 
     * @param {Uint8Array} kemKeyBytes 
     * @returns {Uint8Array}
     */
    packCQRKeys(dsaKeyBytes, kemKeyBytes) {
        const size = 1 + 4 + dsaKeyBytes.length + 4 + kemKeyBytes.length;
        const buffer = new Uint8Array(size);
        const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        
        buffer[0] = this.CQR_VERSION; 
        
        view.setUint32(1, dsaKeyBytes.length, false);
        buffer.set(dsaKeyBytes, 5);
        
        const kemOffset = 5 + dsaKeyBytes.length;
        view.setUint32(kemOffset, kemKeyBytes.length, false);
        buffer.set(kemKeyBytes, kemOffset + 4);
        
        return buffer;
    }

    /**
     * Unpacks a combined CQR key buffer back to DSA and KEM keys
     * @param {Uint8Array} buffer 
     * @returns {{dsaKey: Uint8Array, kemKey: Uint8Array}}
     */
    unpackCQRKeys(buffer) {
        try {
            if (buffer[0] !== this.CQR_VERSION) {
                throw new Error("Unsupported CQR Key Version");
            }
            const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
            
            const dsaLen = view.getUint32(1, false);
            const dsaKey = buffer.slice(5, 5 + dsaLen);
            
            const kemOffset = 5 + dsaLen;
            const kemLen = view.getUint32(kemOffset, false);
            const kemKey = buffer.slice(kemOffset + 4, kemOffset + 4 + kemLen);
            
            return { dsaKey, kemKey };
        } catch (e) { 
            throw new Error("Key is corrupted or tampered"); 
        }
    }

    // --- Cryptographic Operations (AES / KDF) ---

    /**
     * AES-GCM Key Derivation using PBKDF2-SHA512
     * @param {string} password 
     * @param {Uint8Array} saltBytes 
     * @param {number} iterations 
     * @returns {Promise<CryptoKey>}
     */
    async deriveKeyAES(password, saltBytes, iterations = 600000) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw", 
            encoder.encode(password), 
            {name: "PBKDF2"}, 
            false, 
            ["deriveKey"]
        );
        return await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: saltBytes, iterations: iterations, hash: "SHA-512" },
            keyMaterial, 
            { name: "AES-GCM", length: 256 }, 
            false, 
            ["encrypt", "decrypt"]
        );
    }

    /**
     * Encrypts the raw keys for secure offline storage
     * @param {Object} keysObj { cqrPrivateKey: string, cqrPublicKey: string }
     * @param {string} password 
     * @returns {Promise<Object>} Encrypted JSON structure
     */
    async encryptIdentity(keysObj, password) {
        const plaintext = new TextEncoder().encode(JSON.stringify(keysObj));
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await this.deriveKeyAES(password, salt);
        const ciphertext = await crypto.subtle.encrypt({name: "AES-GCM", iv}, key, plaintext);
        
        return {
            developer: this.DEVELOPER_ID, 
            system: this.SYSTEM_ID, 
            type: "CQREncryptedIdentity",
            crypto: {
                kdf: "PBKDF2-SHA512", 
                iterations: 600000,
                salt: this.bytesToBase64url(salt), 
                cipher: "AES-256-GCM",
                iv: this.bytesToBase64url(iv), 
                ciphertext: this.bytesToBase64url(new Uint8Array(ciphertext))
            }
        };
    }

    /**
     * Decrypts the secure offline storage file
     * @param {Object} encryptedObj 
     * @param {string} password 
     * @returns {Promise<Object>} The raw keys object
     */
    async decryptIdentity(encryptedObj, password) {
        try {
            const c = encryptedObj.crypto;
            const salt = this.base64urlToBytes(c.salt);
            const iv = this.base64urlToBytes(c.iv);
            const ciphertext = this.base64urlToBytes(c.ciphertext);
            const key = await this.deriveKeyAES(password, salt, c.iterations);
            const plaintextBuffer = await crypto.subtle.decrypt({name: "AES-GCM", iv}, key, ciphertext);
            return JSON.parse(new TextDecoder().decode(plaintextBuffer));
        } catch (e) { 
            throw new Error("Wrong password or corrupted file"); 
        }
    }

    /**
     * Encrypts a payload securely using a shared secret
     * @param {Uint8Array} sharedSecret 
     * @param {Uint8Array} payloadBytes 
     * @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array}>}
     */
    async encryptAESGCM(sharedSecret, payloadBytes) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await crypto.subtle.importKey('raw', sharedSecret, {name: 'AES-GCM'}, false, ['encrypt']);
        const ciphertext = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, payloadBytes);
        return { iv, ciphertext: new Uint8Array(ciphertext) };
    }

    /**
     * Decrypts a payload securely using a shared secret
     * @param {Uint8Array} sharedSecret 
     * @param {Uint8Array} iv 
     * @param {Uint8Array} ciphertext 
     * @returns {Promise<Uint8Array>}
     */
    async decryptAESGCM(sharedSecret, iv, ciphertext) {
        const key = await crypto.subtle.importKey('raw', sharedSecret, {name: 'AES-GCM'}, false, ['decrypt']);
        const plaintext = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, ciphertext);
        return new Uint8Array(plaintext);
    }

    // --- CQR High-Level API ---

    /**
     * Generates a new ML-DSA-87 and ML-KEM-1024 Identity
     * @returns {{cqrPrivateKey: string, cqrPublicKey: string, raw: Object}}
     */
    generateIdentity() {
        const dsa = this.dsa.keygen();
        const kem = this.kem.keygen();
        
        const cqrPriv = this.bytesToBase64url(this.packCQRKeys(dsa.secretKey, kem.secretKey));
        const cqrPub = this.bytesToBase64url(this.packCQRKeys(dsa.publicKey, kem.publicKey));
        
        return {
            cqrPrivateKey: cqrPriv,
            cqrPublicKey: cqrPub,
            raw: { dsa, kem }
        };
    }

    /**
     * Signs a standard cleartext message
     * @param {string} text Message content
     * @param {string} senderPrivateKey Base64URL encoded CQR Private Key
     * @returns {Object} JSON payload
     */
    signMessage(text, senderPrivateKey) {
        if (!text) throw new Error("الرجاء كتابة رسالة (Message cannot be empty)");
        
        const keys = this.unpackCQRKeys(this.base64urlToBytes(senderPrivateKey));
        const messageBytes = new TextEncoder().encode(text);
        const signature = this.dsa.sign(keys.dsaKey, messageBytes);
        
        return { 
            system: this.SYSTEM_ID, 
            type: "StandardMessage", 
            content: text, 
            signatureBase64url: this.bytesToBase64url(signature) 
        };
    }

    /**
     * Signs a Decentralized Identifier (DID) Document
     * @param {string} didId Custom DID or empty for auto-generation
     * @param {string} serviceEndpoint URL endpoint
     * @param {string} senderPrivateKey Base64URL encoded CQR Private Key
     * @param {string} senderPublicKey Base64URL encoded CQR Public Key
     * @returns {Object} JSON payload
     */
    signDID(didId, serviceEndpoint, senderPrivateKey, senderPublicKey) {
        const keys = this.unpackCQRKeys(this.base64urlToBytes(senderPrivateKey));
        const actualDidId = didId || `did:cqr:${senderPublicKey.substring(0, 16)}`;
        
        const didDoc = {
            "@context":["https://www.w3.org/ns/did/v1"], 
            id: actualDidId,
            verificationMethod:[ { 
                id: `${actualDidId}#cqr-key`, 
                type: "CQR-QuantumKey-L5", 
                controller: actualDidId, 
                publicKeyBase64url: senderPublicKey 
            } ],
            service:[{ 
                id: `${actualDidId}#hq`, 
                type: "LinkedDomains", 
                serviceEndpoint: serviceEndpoint || "http://cqr-crypto.local" 
            }]
        };
        
        const canonicalStr = JSON.stringify(this.canonicalize(didDoc));
        const signature = this.dsa.sign(keys.dsaKey, new TextEncoder().encode(canonicalStr));
        
        return { 
            system: this.SYSTEM_ID, 
            ...didDoc, 
            proof: { 
                type: "CQRDataIntegrityProof", 
                verificationMethod: `${actualDidId}#cqr-key`, 
                proofValue: this.bytesToBase64url(signature) 
            } 
        };
    }

    /**
     * Encrypts and signs a message strictly for a specific receiver
     * @param {string} text Message content
     * @param {string} receiverPublicKey Base64URL encoded CQR Public Key of Receiver
     * @param {string} senderPrivateKey Base64URL encoded CQR Private Key of Sender
     * @returns {Promise<Object>} JSON Encrypted Payload
     */
    async encryptSecretMessage(text, receiverPublicKey, senderPrivateKey) {
        if (!text || !receiverPublicKey) throw new Error("Incomplete data");

        const senderKeys = this.unpackCQRKeys(this.base64urlToBytes(senderPrivateKey));
        const receiverKeys = this.unpackCQRKeys(this.base64urlToBytes(receiverPublicKey));
        
        // 1. Sign the message (using Sender's Private DSA Key)
        const messageBytes = new TextEncoder().encode(text);
        const signature = this.dsa.sign(senderKeys.dsaKey, messageBytes);
        const innerPayloadBytes = new TextEncoder().encode(JSON.stringify({ 
            message: text, 
            signatureBase64url: this.bytesToBase64url(signature) 
        }));

        // 2. Encapsulate Secret using Receiver's ML-KEM Public Key
        const encResult = this.kem.encapsulate(receiverKeys.kemKey);
        const kemCiphertext = encResult.cipherText;
        const sharedSecret = encResult.sharedSecret;
        
        // 3. Encrypt payload using AES-GCM and the shared secret
        const { iv, ciphertext } = await this.encryptAESGCM(sharedSecret, innerPayloadBytes);

        return {
            system: this.SYSTEM_ID, 
            type: "CQREncryptedMessage",
            encapsulatedKey: this.bytesToBase64url(kemCiphertext),
            iv: this.bytesToBase64url(iv), 
            ciphertext: this.bytesToBase64url(ciphertext)
        };
    }

    /**
     * Verifies cleartext messages (StandardMessage or DID)
     * @param {Object} parsedDoc The received JSON payload
     * @param {string} senderPublicKey Base64URL encoded CQR Public Key
     * @returns {boolean} Is Valid Signature
     */
    verifyCleartextMessage(parsedDoc, senderPublicKey) {
        const senderKeys = this.unpackCQRKeys(this.base64urlToBytes(senderPublicKey));
        const senderDsaBytes = senderKeys.dsaKey;

        if (parsedDoc.type === "StandardMessage") {
            return this.dsa.verify(
                senderDsaBytes, 
                new TextEncoder().encode(parsedDoc.content), 
                this.base64urlToBytes(parsedDoc.signatureBase64url)
            );
        } else if (parsedDoc.proof) {
            const signatureBytes = this.base64urlToBytes(parsedDoc.proof.proofValue);
            const docNoProof = { ...parsedDoc }; 
            delete docNoProof.proof; 
            delete docNoProof.system;
            
            return this.dsa.verify(
                senderDsaBytes, 
                new TextEncoder().encode(JSON.stringify(this.canonicalize(docNoProof))), 
                signatureBytes
            );
        } else {
            throw new Error("Unsupported cleartext format");
        }
    }

    /**
     * Decrypts and verifies a secret message (Military Grade Error Handling)
     * @param {Object} parsedDoc The received CQREncryptedMessage JSON payload
     * @param {string} senderPublicKey Base64URL encoded CQR Public Key of Sender
     * @param {string} receiverPrivateKey Base64URL encoded CQR Private Key of Receiver
     * @returns {Promise<{isValid: boolean, message: string}>}
     */
    async decryptSecretMessage(parsedDoc, senderPublicKey, receiverPrivateKey) {
        if (parsedDoc.type !== "CQREncryptedMessage") {
            throw new Error("This payload is not a valid encrypted message");
        }

        let receiverKeys, senderKeys;
        try {
            receiverKeys = this.unpackCQRKeys(this.base64urlToBytes(receiverPrivateKey));
            senderKeys = this.unpackCQRKeys(this.base64urlToBytes(senderPublicKey));
        } catch(e) {
            throw new Error("Key initialization error: Please ensure that the recipient's private key and the sender's public key are entered correctly");
        }

        // 1. Quantum Shared Key Extraction (Decapsulation)
        let sharedSecret;
        try {
            sharedSecret = this.kem.decapsulate(
                this.base64urlToBytes(parsedDoc.encapsulatedKey), 
                receiverKeys.kemKey
            );
        } catch(e) {
            throw new Error("Fatal error during key extraction");
        }
        
        // 2. Try Decryption (Decryption)
        let decryptedBytes;
        try {
            decryptedBytes = await this.decryptAESGCM(
                sharedSecret, 
                this.base64urlToBytes(parsedDoc.iv), 
                this.base64urlToBytes(parsedDoc.ciphertext)
            );
        } catch (error) {
            throw new Error("Decryption Failed 🔒: The private key provided does not match the intended recipient, or the message has been tampered with in transit");
        }
        
        // 3. Reading internal message contents
        let innerJson;
        try {
            innerJson = JSON.parse(new TextDecoder().decode(decryptedBytes));
        } catch(error) {
            throw new Error("Decrypted, but the content format is invalid");
        }
        
        // 4. Verifying the sender's digital signature (Verification)
        let isValid = false;
        try {
            isValid = this.dsa.verify(
                senderKeys.dsaKey, 
                new TextEncoder().encode(innerJson.message), 
                this.base64urlToBytes(innerJson.signatureBase64url)
            );
        } catch (error) {
            throw new Error("A technical error occurred while verifying the sender's digital signature");
        }

        if (!isValid) {
            throw new Error("High Security Alert: Decryption successful, but digital signature is forged and does not match the sender's public key (Possible impersonation)");
        }

        return { isValid, message: innerJson.message };
    }
}

// Export for Node.js / ES6 Environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CQRCrypto };
} else {
    // Browser Support (Global Window)
    window.CQRCrypto = CQRCrypto;
}
