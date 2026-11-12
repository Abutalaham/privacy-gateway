export const samples = [
  {
    id: "loan",
    name: "English loan form",
    docType: "loan_application",
    text: `LOAN APPLICATION FORM
Applicant Name: Priya Naik
Address: Flat 24B, Sai Apartments, Madhapur, Hyderabad 500004
Mobile: 9361158878   Email: priya.naik76@yahoo.in
Aadhaar: 6940-7816-1849
PAN: UGYCN0750X
Loan requested: Rs. 1250000 for a two-wheeler purchase over 36 months.`,
  },
  {
    id: "kyc",
    name: "KYC record",
    docType: "kyc",
    text: `KYC VERIFICATION
Customer name: Meera Reddy
Address: 18 Lake View Road, Indiranagar, Bengaluru 560038
Phone: 9845012345
Email: meera.reddy@example.in
Aadhaar: 2363-1234-5678
PAN: ABCDE1234F
Please verify the submitted identity documents.`,
  },
  {
    id: "hinglish",
    name: "Hinglish support ticket",
    docType: "customer_support",
    text: `Support ticket: Mera naam Suresh Gowda hai. Mera registered number 9876543210 hai.
Order refund abhi tak receive nahi hua. Please meri request check karke update bhejiye.
Email: suresh.gowda@example.com`,
  },
  {
    id: "kannada",
    name: "Kannada-English ticket",
    docType: "customer_support",
    text: `Customer support request
Nanna hesaru Chaitra Hegde. My phone number is 9845011223.
Address: No. 12, 4th Cross, Jayanagar, Bengaluru - 560011.
ನನ್ನ ಖಾತೆಯಲ್ಲಿ ಪಾವತಿ ಕಾಣಿಸುತ್ತಿಲ್ಲ. Please check the latest transaction.`,
  },
  {
    id: "insurance",
    name: "Insurance claim",
    docType: "insurance_claim",
    text: `HEALTH INSURANCE CLAIM
Policy holder: Arjun Menon
Address: 7 Palm Grove, Kakkanad, Kochi 682030
Contact: 9895012345 | arjun.menon@example.in
Member PAN: PQRSX1234G
Claim request: Please review the hospital reimbursement for Rs. 78500.`,
  },
];

export const fallbackPolicies: Record<string, { description: string; default: string; actions: Record<string, string> }> = {
  default: { description: "Mask every detected PII value with a reversible typed placeholder.", default: "mask", actions: {} },
  kyc_verification: { description: "KYC review: mask everything, reversible.", default: "mask", actions: {} },
  customer_support: { description: "Support tickets: mask everything, reversible.", default: "mask", actions: {} },
  loan_underwriting: { description: "Loan underwriting: mask everything, reversible.", default: "mask", actions: {} },
  analytics_fpe: {
    description: "Identity numbers become format-preserving tokens for downstream validators.",
    default: "mask",
    actions: { AADHAAR: "fpe", PAN: "fpe", GSTIN: "fpe", PASSPORT: "fpe", VOTER_ID: "fpe", PHONE: "fpe" },
  },
  marketing: {
    description: "Government IDs are blocked; other contact data is irreversibly redacted.",
    default: "mask",
    actions: { AADHAAR: "block", PAN: "block", PASSPORT: "block", VOTER_ID: "block", GSTIN: "redact", PHONE: "redact", EMAIL: "redact", ADDRESS: "redact" },
  },
};

export const entityColors: Record<string, string> = {
  PERSON: "entity-person",
  ADDRESS: "entity-address",
  AADHAAR: "entity-aadhaar",
  PAN: "entity-pan",
  GSTIN: "entity-gstin",
  VOTER_ID: "entity-voter",
  PASSPORT: "entity-passport",
  PHONE: "entity-phone",
  EMAIL: "entity-email",
  CREDIT_CARD: "entity-aadhaar",
  BANK_ACCOUNT: "entity-phone",
  IP_ADDRESS: "entity-address",
  DATE_OF_BIRTH: "entity-passport",
};

export const metricsFallback = {
  pii_leakage_count: 0,
  reinsertion: { accuracy: 1, restored_correctly: 310, total_checked: 310 },
  latency_ms: { gateway_overhead_p95: 3.63 },
  per_type_overlap: {
    PERSON: { precision: 0.993, recall: 1, f1: 0.996 },
    ADDRESS: { precision: 1, recall: 1, f1: 1 },
    AADHAAR: { precision: 0.979, recall: 1, f1: 0.989 },
    PAN: { precision: 1, recall: 1, f1: 1 },
    GSTIN: { precision: 1, recall: 1, f1: 1 },
    VOTER_ID: { precision: 1, recall: 1, f1: 1 },
    PASSPORT: { precision: 1, recall: 1, f1: 1 },
    PHONE: { precision: 1, recall: 1, f1: 1 },
    EMAIL: { precision: 1, recall: 1, f1: 1 },
  },
};
