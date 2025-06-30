# Digital Signature

Tanda tangan sudah memegang peranan krusial sebagai alat otentikasi utama pada dokumen cetak. Tanda tangan memiliki fungsi sebagai bukti atas keaslian dokumen dan persetujuan dari para pihak yang bersangkutan.

Karakteristik:
- bukti otentik
- tidak dapat dipindah
- tidak dapat dilupakan
- anti-penyangkalan

Fungsi esensial tanda tangan kemudian diadaptasi dalam tanda tangan digital (digital signature), di mana luas penerapannya dalam data digital (seperti pesan, dokumen elektronik, dan lain-lain). Perlu diingat, coretan yang digunakan dalam tanda tangan cetak tidak memenuhi syarat kebutuhan keamanan dan otentikasi di lingkungan digital.

Untuk menjamin keaslian dan integritas data, tanda tangan digital memanfaatkan kriptografi dalam algoritma yang digunakan. Salah satu cara pembuatan tanda tangan digital adalah seperti berikut:
1. Buat hash dari pesan yang akan dikirim. (`h = H(M)`, `h` adalah hasil hash pengirim, `H()` adalah fungsi hash)
1. Enkripsi hash dengan kriptografi kunci asimetris, menggunakan kunci privat pengirim. (`S = h^(SK) mod n`, `^` adalah pangkat, `S` adalah digital signature, `SK` adalah private key dari pengirim, `n` adalah batas ruang)
1. Penerima melakukan menghitung hash secara mandiri. (`h' = H(M)`, `h'` adalah hasil hash penerima, `H()` adalah fungsi hash)
1. Penerima melakukan dekripsi hash pesan pengirim dengan kunci publik pengirim. (`h = S^(PK) mod n`)
1. Penerima membandingkan hash yang dihitung secara mandiri dengan hash hasil dekripsi. Jika hasil tidak sama, maka pesan telah diubah di perjalanan.

Dengan fungsi hash yang baik, perubahan sekecil apapun di pesan akan memberikan perbedaan yang signifikan di hasil fungsi hash. Namun jika hash langsung dikirim begitu saja dengan pesan, pihak ketiga dapat mengubah pesan sekaligus hasil hash asli. Intisari dari alur digital signature adalah berada di fungsi hash, bagaimana hash pesan asli dikirim, dan bagaimana hash asli dapat diverifikasi secara independen oleh penerima.

## Contoh Digital Signature: Elgamal Digital Signature

Pengirim:
1. Memiliki bilangan prima besar `p`.
1. Akar primitif `g` modulo `p`.
1. `a`, bilangan yang memenuhi `(1 <= a <= p-1)`, sebagai kunci privat.
1. `A = g^3 mod p`, dengan `A` adalah kunci publik.
1. `(p,g)` dipublikasikan ke semua pihak.

Signing:
1. `D = H(m)`, di mana `D` adalah hasil hash, `H()` adalah fungsi hash, `m` adalah pesan.
1. Pilih bilangan acak `k` yang relatif prima terhadap `p-1`.
1. Hitung `S1 = g^k mod p`, `S2 = k^(-1) (D-a.S1) mod (p-1)`. `(S1,S2)` adalah tanda tangan digital.

Verifikasi:
1. Penerima menerima `(S1,S2)`.
1. Hitung `D = H(m)`, di mana `D` adalah hasil hash, `H()` adalah fungsi hash, `m` adalah pesan yang diterima.
1. Hitung `V1 = A^(S1) S1^(S2) mod p`, `V2 = g^D mod p`.
1. Jika `V1 = V2`, maka tanda tangan valid.
