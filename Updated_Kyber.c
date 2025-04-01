#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// Kyber parameters (simplified for demonstration)
#define N 256        // polynomial degree
#define Q 3329       // modulus
#define K 2          // dimension parameter (K=2 for Kyber-512)
#define ETA1 3       // noise parameter for secret key
#define ETA2 2       // noise parameter for error
#define DU 10        // compression parameter for u
#define DV 4         // compression parameter for v

// Helper macros
#define MODQ(X) ((((X) % Q) + Q) % Q)

// Polynomial type
typedef struct {
    int16_t coeffs[N];
} poly_t;

// Polynomial vector type
typedef struct {
    poly_t vec[K];
} polyvec_t;

// Key pair structure
typedef struct {
    unsigned char seed_a[32];
    polyvec_t t;     // public key
    polyvec_t s;     // private key
} keypair_t;

// Ciphertext structure
typedef struct {
    polyvec_t u;
    poly_t v;
} ciphertext_t;

// Performance metrics structure
typedef struct {
    double keygen_time;
    double encaps_time;
    double decaps_time;
    double total_time;
} performance_metrics_t;

// ----- Helper functions -----

// Initialize random number generator
void init_rng() {
    srand(time(NULL));
}

// Generate a random byte
unsigned char rand_byte() {
    return (unsigned char)(rand() & 0xFF);
}

// Generate a uniform random polynomial
void gen_uniform_poly(poly_t *p, const unsigned char *seed, int seed_offset) {
    // In a real implementation, this would use a proper XOF
    // Here we just use the seed to set the rand() state
    int i;
    unsigned long seed_val = 0;
    for ( i = 0; i < 4 && i < 32; i++) {
        seed_val = (seed_val << 8) | seed[i];
    }
    srand(seed_val + seed_offset);
    
    for ( i = 0; i < N; i++) {
        p->coeffs[i] = rand() % Q;
    }
}

// Generate a polynomial with coefficients from centered binomial distribution
void gen_binomial_poly(poly_t *p, int eta) {
	int i,j;
    for ( i = 0; i < N; i++) {
        int sum = 0;
        for ( j = 0; j < 2 * eta; j++) {
            sum += (rand() % 2);
        }
        p->coeffs[i] = sum - eta;
    }
}

// Add two polynomials: result = a + b
void poly_add(poly_t *result, const poly_t *a, const poly_t *b) {
	int i;
    for ( i = 0; i < N; i++) {
        result->coeffs[i] = MODQ(a->coeffs[i] + b->coeffs[i]);
    }
}

// Subtract two polynomials: result = a - b
void poly_sub(poly_t *result, const poly_t *a, const poly_t *b) {
	int i;
    for ( i = 0; i < N; i++) {
        result->coeffs[i] = MODQ(a->coeffs[i] - b->coeffs[i]);
    }
}

// Multiply two polynomials modulo (X^N + 1) and Q
// This is a simplified implementation that is not efficient
void poly_mul(poly_t *result, const poly_t *a, const poly_t *b) {
	int i,j;
    int16_t temp[2*N - 1] = {0};
    
    // Standard polynomial multiplication
    for ( i = 0; i < N; i++) {
        for ( j = 0; j < N; j++) {
            temp[i+j] = MODQ(temp[i+j] + a->coeffs[i] * b->coeffs[j]);
        }
    }
    
    // Reduction modulo X^N + 1
    for ( i = 0; i < N; i++) {
        result->coeffs[i] = temp[i];
    }
    for ( i = N; i < 2*N - 1; i++) {
        result->coeffs[i-N] = MODQ(result->coeffs[i-N] - temp[i]);
    }
}

// Multiply polynomial vector a by polynomial vector b
void polyvec_mul(poly_t *result, const polyvec_t *a, const polyvec_t *b) {
	int i;
    poly_t temp;
    
    // Initialize result to zero
    memset(result->coeffs, 0, sizeof(result->coeffs));
    
    // Compute sum of products
    for ( i = 0; i < K; i++) {
        poly_mul(&temp, &a->vec[i], &b->vec[i]);
        poly_add(result, result, &temp);
    }
}

// Compress polynomial from Q bits to d bits per coefficient
void compress(poly_t *result, const poly_t *p, int d) {
	int i;
    double factor = (1 << d) / (double)Q;
    for ( i = 0; i < N; i++) {
        result->coeffs[i] = (int16_t)(factor * p->coeffs[i] + 0.5) & ((1 << d) - 1);
    }
}

// Decompress polynomial from d bits to Q bits per coefficient
void decompress(poly_t *result, const poly_t *p, int d) {
	int i;
    double factor = Q / (double)(1 << d);
    for ( i = 0; i < N; i++) {
        result->coeffs[i] = (int16_t)(factor * p->coeffs[i] + 0.5) % Q;
    }
}

// Compress polynomial vector
void polyvec_compress(polyvec_t *result, const polyvec_t *p, int d) {
	int i;
    for ( i = 0; i < K; i++) {
        compress(&result->vec[i], &p->vec[i], d);
    }
}

// Decompress polynomial vector
void polyvec_decompress(polyvec_t *result, const polyvec_t *p, int d) {
	int i;
    for ( i = 0; i < K; i++) {
        decompress(&result->vec[i], &p->vec[i], d);
    }
}

// ----- Kyber Key Generation -----

void keygen(keypair_t *keypair) {
	int i,j;
    polyvec_t e;
    
    // Generate random seed
    for ( i = 0; i < 32; i++) {
        keypair->seed_a[i] = rand_byte();
    }
    
    // Generate the secret vector s (K polynomials with small coefficients)
    for ( i = 0; i < K; i++) {
        gen_binomial_poly(&keypair->s.vec[i], ETA1);
    }
    
    // Generate error vector e (K polynomials with small coefficients)
    for ( i = 0; i < K; i++) {
        gen_binomial_poly(&e.vec[i], ETA2);
    }
    
    // Compute public key t = A·s + e
    // In this simplified version, we compute A·s directly
    // In practice, we would compute each component separately
    for ( i = 0; i < K; i++) {
        poly_t temp;
        memset(&keypair->t.vec[i], 0, sizeof(poly_t));
        
        for ( j = 0; j < K; j++) {
            poly_t a_ij;
            gen_uniform_poly(&a_ij, keypair->seed_a, i*K + j);
            poly_mul(&temp, &a_ij, &keypair->s.vec[j]);
            poly_add(&keypair->t.vec[i], &keypair->t.vec[i], &temp);
        }
        
        poly_add(&keypair->t.vec[i], &keypair->t.vec[i], &e.vec[i]);
    }
}

// ----- Kyber Encapsulation -----

void encaps(ciphertext_t *ciphertext, unsigned char *shared_secret, const keypair_t *keypair) {
	int i,j;
    poly_t m, temp;
    polyvec_t r;
    
    // Generate random message m
    for ( i = 0; i < N; i++) {
        m.coeffs[i] = rand() % 2;
    }
    
    // Generate random vector r (K polynomials with small coefficients)
    for ( i = 0; i < K; i++) {
        gen_binomial_poly(&r.vec[i], ETA1);
    }
    
    // Compute u = A^T·r
    for ( j = 0; j < K; j++) {
        memset(&ciphertext->u.vec[j], 0, sizeof(poly_t));
        
        for ( i = 0; i < K; i++) {
            poly_t a_ij;
            gen_uniform_poly(&a_ij, keypair->seed_a, i*K + j);
            poly_mul(&temp, &a_ij, &r.vec[i]);
            poly_add(&ciphertext->u.vec[j], &ciphertext->u.vec[j], &temp);
        }
    }
    
    // Compute v = t^T·r + m·?q/2?
    memset(&ciphertext->v, 0, sizeof(poly_t));
    polyvec_mul(&ciphertext->v, &keypair->t, &r);
    
    // Add message scaled by q/2
    for ( i = 0; i < N; i++) {
        ciphertext->v.coeffs[i] = MODQ(ciphertext->v.coeffs[i] + m.coeffs[i] * (Q/2));
    }
    
    // Compress u and v
    polyvec_t u_temp = ciphertext->u;
    polyvec_compress(&ciphertext->u, &u_temp, DU);
    
    poly_t v_temp = ciphertext->v;
    compress(&ciphertext->v, &v_temp, DV);
    
    // In a real implementation, we would hash the message and ciphertext
    // to get the shared secret. Here we just copy part of m for demo purposes.
    for ( i = 0; i < 32; i++) {
        shared_secret[i] = (i < N/8) ? 
            (m.coeffs[i*8] | (m.coeffs[i*8+1] << 1) | (m.coeffs[i*8+2] << 2) | 
             (m.coeffs[i*8+3] << 3) | (m.coeffs[i*8+4] << 4) | (m.coeffs[i*8+5] << 5) | 
             (m.coeffs[i*8+6] << 6) | (m.coeffs[i*8+7] << 7)) : 0;
    }
}

// ----- Kyber Decapsulation -----

void decaps(unsigned char *shared_secret, const ciphertext_t *ciphertext, const keypair_t *keypair) {
	int i;
    ciphertext_t ct_decompressed;
    poly_t m_prime;
    
    // Decompress u and v
    polyvec_decompress(&ct_decompressed.u, &ciphertext->u, DU);
    decompress(&ct_decompressed.v, &ciphertext->v, DV);
       
    // Compute m' = v - s^T·u
    polyvec_mul(&m_prime, &keypair->s, &ct_decompressed.u);
    poly_sub(&m_prime, &ct_decompressed.v, &m_prime);
    
    // Convert to binary (if coefficient is closer to q/2 than to 0, it's a 1)
    for ( i = 0; i < N; i++) {
        int16_t coeff = m_prime.coeffs[i];
        if (coeff > Q/4 && coeff < 3*Q/4)
            m_prime.coeffs[i] = 1;
        else
            m_prime.coeffs[i] = 0;
    }
    
    // In a real implementation, we would hash the message and ciphertext
    // to get the shared secret. Here we just copy part of m' for demo purposes.
    for ( i = 0; i < 32; i++) {
        shared_secret[i] = (i < N/8) ? 
            (m_prime.coeffs[i*8] | (m_prime.coeffs[i*8+1] << 1) | (m_prime.coeffs[i*8+2] << 2) | 
             (m_prime.coeffs[i*8+3] << 3) | (m_prime.coeffs[i*8+4] << 4) | (m_prime.coeffs[i*8+5] << 5) | 
             (m_prime.coeffs[i*8+6] << 6) | (m_prime.coeffs[i*8+7] << 7)) : 0;
    }
}

// Function to run multiple iterations and collect performance metrics
performance_metrics_t benchmark_kyber(int iterations) {
	int i;
    performance_metrics_t metrics = {0};
    double start_time, end_time;
    
    for ( i = 0; i < iterations; i++) {
        keypair_t keypair;
        ciphertext_t ciphertext;
        unsigned char sender_shared_secret[32];
        unsigned char receiver_shared_secret[32];
        
        // Measure key generation time
        start_time = (double)clock() / CLOCKS_PER_SEC;
        keygen(&keypair);
        end_time = (double)clock() / CLOCKS_PER_SEC;
        metrics.keygen_time += end_time - start_time;
        
        // Measure encapsulation time
        start_time = (double)clock() / CLOCKS_PER_SEC;
        encaps(&ciphertext, sender_shared_secret, &keypair);
        end_time = (double)clock() / CLOCKS_PER_SEC;
        metrics.encaps_time += end_time - start_time;
        
        // Measure decapsulation time
        start_time = (double)clock() / CLOCKS_PER_SEC;
        decaps(receiver_shared_secret, &ciphertext, &keypair);
        end_time = (double)clock() / CLOCKS_PER_SEC;
        metrics.decaps_time += end_time - start_time;
    }
    
    // Calculate averages
    metrics.keygen_time /= iterations;
    metrics.encaps_time /= iterations;
    metrics.decaps_time /= iterations;
    metrics.total_time = metrics.keygen_time + metrics.encaps_time + metrics.decaps_time;
    
    return metrics;
}

// ----- Example usage -----

void print_hex(const unsigned char *data, int len) {
	int i;
    for ( i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i != len - 1)
            printf("\n");
    }
    printf("\n");
}

int main() {
    keypair_t keypair;
    ciphertext_t ciphertext;
    unsigned char sender_shared_secret[32];
    unsigned char receiver_shared_secret[32];
    clock_t start_overall, end_overall;
    double single_run_time;
    
    // Initialize RNG
    init_rng();
    
    printf("CRYSTALS-Kyber Demo (simplified C implementation)\n");
    printf("------------------------------------------------\n\n");
    
    // Time the overall single execution
    start_overall = clock();
    
    // Generate key pair
    printf("Generating key pair...\n");
    clock_t start = clock();
    keygen(&keypair);
    clock_t end = clock();
    printf("Key generation completed in %.6f seconds\n\n", (double)(end - start) / CLOCKS_PER_SEC);
    
    // Encapsulate a shared secret
    printf("Encapsulating shared secret...\n");
    start = clock();
    encaps(&ciphertext, sender_shared_secret, &keypair);
    end = clock();
    printf("Encapsulation completed in %.6f seconds\n\n", (double)(end - start) / CLOCKS_PER_SEC);
    
    // Decapsulate the shared secret
    printf("Decapsulating shared secret...\n");
    start = clock();
    decaps(receiver_shared_secret, &ciphertext, &keypair);
    end = clock();
    printf("Decapsulation completed in %.6f seconds\n\n", (double)(end - start) / CLOCKS_PER_SEC);
    
    end_overall = clock();
    single_run_time = (double)(end_overall - start_overall) / CLOCKS_PER_SEC;
    
    // Display shared secrets
    printf("Sender's shared secret:\n");
    print_hex(sender_shared_secret, 32);
    
    printf("\nReceiver's shared secret:\n");
    print_hex(receiver_shared_secret, 32);
    
    // Verify that both parties have the same shared secret
    int match = memcmp(sender_shared_secret, receiver_shared_secret, 32) == 0;
    printf("\nShared secrets match: %s\n", match ? "YES" : "NO");
    
    printf("\nTotal time for single execution: %.6f seconds\n\n", single_run_time);
    
    // Benchmark with multiple iterations
    printf("Running benchmark with multiple iterations...\n");
    int iterations = 100;
    printf("Number of iterations: %d\n", iterations);
    
    performance_metrics_t metrics = benchmark_kyber(iterations);
    
    printf("\nPerformance Metrics (averaged over %d iterations):\n", iterations);
    printf("--------------------------------------------------\n");
    printf("Key Generation: %.6f seconds\n", metrics.keygen_time);
    printf("Encapsulation:  %.6f seconds\n", metrics.encaps_time);
    printf("Decapsulation:  %.6f seconds\n", metrics.decaps_time);
    printf("Total:          %.6f seconds\n", metrics.total_time);
    
    // Compare to single execution
    printf("\nEfficiency Analysis:\n");
    printf("-------------------\n");
    printf("Our implementation is a simplified educational version of Kyber.\n");
    printf("The naive polynomial multiplication has O(n^2) complexity instead of\n");
    printf("the O(n log n) that would be achieved with NTT-based multiplication.\n");
    printf("\nReference implementations of Kyber are typically:\n");
    printf("- 10-100x faster on desktop CPUs\n");
    printf("- Much more memory efficient\n");
    printf("- Constant-time to prevent side-channel attacks\n");
    
    return 0;
}
