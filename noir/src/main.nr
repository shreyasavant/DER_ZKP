global PF_MAX: u32 = 1000;

fn merkle_root(leaf: Field, index: Field, siblings: [Field; 3]) -> Field {
    let bits: [bool; 3] = index.to_le_bits();
    let mut cur = leaf;
    for i in 0..3 {
        let (l, r) = if bits[i] { (siblings[i], cur) } else { (cur, siblings[i]) };
        cur = std::hash::pedersen_hash([l, r]);
    }
    cur
}

fn main(
    merkle_root_pub: pub Field,
    v_min: pub u32,
    v_max: pub u32,
    f_min: pub u32,
    f_max: pub u32,
    pf_min: pub u32,
    p_max: pub u32,
    r_max: pub u32,
    v: [u32; 8],
    f: [u32; 8],
    pf: [u32; 8],
    p: [u32; 8],
    q: [u32; 8],
    path_elements: [[Field; 3]; 8],
    path_indices: [Field; 8],
) {
    for t in 0..8 {
        assert(v[t] >= v_min);
        assert(v[t] <= v_max);
        assert(f[t] >= f_min);
        assert(f[t] <= f_max);
        assert(pf[t] >= pf_min);
        assert(pf[t] <= PF_MAX);
        assert(p[t] <= p_max);

        let leaf = std::hash::pedersen_hash(
            [v[t] as Field, f[t] as Field, pf[t] as Field, p[t] as Field, q[t] as Field],
        );

        let computed = merkle_root(leaf, path_indices[t], path_elements[t]);
        assert(computed == merkle_root_pub);
    }

    for t in 1..8 {
        let shifted: u32 =
            (p[t] as Field + r_max as Field - p[t - 1] as Field) as u32;
        assert(shifted <= 2 * r_max);
    }
}
