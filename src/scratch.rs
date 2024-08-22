fn gen_test_case<A: Aead, Kdf: KdfTrait, Kem: TestableKem, R: CryptoRng + RngCore>(mode: u8, csprng: &mut R) -> MainTestVector {
        let info = b"4f6465206f6e2061204772656369616e2055726e"; // same as RFC 9180 test vectors
        let ikm_eph = gen_ikm::<Kem, R>(csprng);
        let (sk_eph, pk_eph) = Kem::derive_keypair(&ikm_eph);
        let ikm_recip = gen_ikm::<Kem, R>(csprng);
        let recip_keypair = Kem::derive_keypair(&ikm_recip);

        let (mode_s, ikm_sender) = match mode {
            0x00 => {
                (make_op_mode_s::<Kem>(mode, None, None, None), None)
            },
            0x01 => {
                (make_op_mode_s::<Kem>(mode, None, Some(PSK), Some(PSK_ID)), None)
            },
            0x02 => {
                let ikm_sender = gen_ikm::<Kem, R>(csprng);
                (make_op_mode_s::<Kem>(mode, Some(Kem::derive_keypair(&ikm_sender)), None, None), Some(ikm_sender))
            },
            0x03 => {
                let ikm_sender = gen_ikm::<Kem, R>(csprng);
                (make_op_mode_s::<Kem>(mode, Some(Kem::derive_keypair(&ikm_sender)), Some(PSK), Some(PSK_ID)), Some(ikm_sender))
            },
        };


// go to increment nonce
func (ctx *context) computeNonce() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, ctx.Seq)

	Nn := len(ctx.BaseNonce)
	nonce := make([]byte, Nn)
	copy(nonce, ctx.BaseNonce)
	for i := range buf {
		nonce[Nn-8+i] ^= buf[i]
	}

	ctx.nonces = append(ctx.nonces, nonce)
	return nonce
}

// TODO derive secret, key, base_nonce, exporter_secret

        // let secret = labeled_extract::<Kdf>(&shared_secret.0, &suite_id, b"secret", psk.unwrap_or(&[]));

        // // Derive the key
        // let mut key = vec![0u8; Nk];
        // labeled_expand::<Kdf>(&secret, &suite_id, b"key", &key_schedule_context, &mut key);

        // // Derive the base_nonce
        // let mut base_nonce = vec![0u8; Nn];
        // labeled_expand::<Kdf>(&secret, &suite_id, b"base_nonce", &key_schedule_context, &mut base_nonce);

        // // Derive the exporter_secret
        // let mut exporter_secret = vec![0u8; Nh];
        // labeled_expand::<Kdf>(&secret, &suite_id, b"exp", &key_schedule_context, &mut exporter_secret);

        // In KeySchedule(),
        //   secret = LabeledExtract(shared_secret, "secret", psk)
        //   key = LabeledExpand(secret, "key", key_schedule_context, Nk)
        //   base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
        //   exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, Nh)
        // Instead of `secret` we derive an HKDF context which we run .expand() on to derive the
        // key-nonce pair.