/// Calculate Shannon entropy of a string.
/// High entropy (> 4.5) often indicates random/secret values.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    let mut freq = [0u32; 256];

    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }

    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns true if the string looks like a high-entropy secret.
/// Requires minimum 16 chars and entropy > 4.5 bits/char.
pub fn is_high_entropy(s: &str) -> bool {
    s.len() >= 16 && shannon_entropy(s) > 4.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn single_char_repeated() {
        assert_eq!(shannon_entropy("aaaaaaaaaaaaaaaa"), 0.0);
    }

    #[test]
    fn low_entropy_string() {
        // Repetitive string — low entropy
        assert!(!is_high_entropy("aaaaaaaaaaaaaaaa"));
        assert!(!is_high_entropy("aabbccddaabbccdd"));
    }

    #[test]
    fn high_entropy_string() {
        // Random base64-like string
        assert!(is_high_entropy("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"));
    }

    #[test]
    fn too_short_even_if_random() {
        assert!(!is_high_entropy("aB3dE5f"));
    }

    #[test]
    fn real_api_key_like() {
        assert!(is_high_entropy("sk_live_4eC39HqLyjWDarjtT1zdp7dc"));
    }

    #[test]
    fn normal_path_is_low_entropy() {
        assert!(!is_high_entropy("/usr/local/bin/node"));
    }

    #[test]
    fn entropy_increases_with_diversity() {
        let low = shannon_entropy("aaaa");
        let high = shannon_entropy("abcd");
        assert!(high > low);
    }
}
