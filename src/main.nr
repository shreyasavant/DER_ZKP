fn main(x: Field) {
    let bits: [u1; 3] = x.to_le_bits();
    let _b = bits[0] as bool;
    let _r: Field = std::hash::pedersen_hash([x, x]);
}
