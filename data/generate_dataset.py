"""Seeded generator for ~50 synthetic Indian documents with gold PII spans.
Run:  python -m data.generate_dataset   ->  data/synthetic_docs.json
All identifiers are random/synthetic (valid formats + valid checksums where applicable)."""
import json
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gateway.checksums import gstin_check_char, verhoeff_check_digit  # noqa: E402

SEED = 42
FIRST = ["Rahul", "Priya", "Amit", "Suresh", "Anjali", "Ramesh", "Lakshmi", "Manjunath", "Vijay", "Sunita", "Harish",
         "Nandini", "Basavaraj", "Chaitra", "Farhan", "Zoya", "Gurpreet", "Tanvi", "Abhishek", "Shilpa", "Kiran", "Meena",
         "Sanjay", "Pooja", "Ravi", "Anita", "Mahesh", "Divya", "Prakash", "Rekha", "Imran", "Swati", "Naveen", "Deepa",
         "Yogesh", "Bhavana", "Karthik", "Ayesha", "Sandeep", "Usha"]
LAST = ["Sharma", "Patel", "Gowda", "Kumar", "Singh", "Reddy", "Nair", "Iyer", "Banerjee", "Chatterjee", "Kulkarni",
        "Deshpande", "Khan", "Siddiqui", "Pillai", "Menon", "Bhat", "Naik", "Kaur", "Malhotra", "Saxena", "Hegde", "Patil",
        "Shetty", "Joshi", "Mehta", "Rao", "Verma", "Gupta", "Yadav", "Ghosh", "Mishra", "Jain", "Chowdhury", "Acharya"]
CITIES = [("Bengaluru", "560", ["Jayanagar", "Indiranagar", "Malleshwaram", "Whitefield", "HSR Layout"]),
          ("Mysuru", "570", ["Vijayanagar", "Kuvempunagar", "Saraswathipuram"]),
          ("Davangere", "577", ["MCC B Block", "Vidyanagar", "PJ Extension"]),
          ("Mumbai", "400", ["Andheri East", "Dadar West", "Powai"]), ("Delhi", "110", ["Karol Bagh", "Dwarka Sector 7", "Lajpat Nagar"]),
          ("Chennai", "600", ["Adyar", "T Nagar", "Velachery"]), ("Hyderabad", "500", ["Madhapur", "Banjara Hills", "Kukatpally"]),
          ("Pune", "411", ["Kothrud", "Hadapsar", "Baner"]), ("Kolkata", "700", ["Salt Lake", "Behala", "Garia"]),
          ("Ahmedabad", "380", ["Navrangpura", "Satellite", "Maninagar"])]
STATES = ["29", "27", "07", "33", "36", "24", "19"]
COMPANIES = ["Sri Venkateshwara Traders", "Kaveri Agro Foods", "Bharat Steel Works", "Shakti Textiles", "Anand Electricals"]
PURPOSES = ["home renovation", "two-wheeler purchase", "working capital", "education", "medical expenses"]


def name(r): return f"{r.choice(FIRST)} {r.choice(LAST)}" if r.random() > .15 else f"{r.choice(FIRST)} {r.choice('ABKMRSV')}. {r.choice(LAST)}"
def phone(r): return f"{r.choice('6789')}{r.randint(0, 9999):04d}{r.randint(0, 99999):05d}"[:10] if r.random() > .3 else f"+91 {r.choice('6789')}{r.randint(0,9999):04d} {r.randint(0,99999):05d}"[:15]
def email(r, n): return f"{re.sub(r'[^a-z]', '.', n.lower()).strip('.')}{r.randint(1, 99)}@{r.choice(['gmail.com', 'yahoo.in', 'outlook.com'])}"


def aadhaar(r):
    body = str(r.randint(2, 9)) + "".join(str(r.randint(0, 9)) for _ in range(10))
    num = body + verhoeff_check_digit(body) if r.random() > .2 else str(r.randint(1, 9)) + "".join(str(r.randint(0, 9)) for _ in range(11))
    return r.choice([f"{num[:4]} {num[4:8]} {num[8:]}", f"{num[:4]}-{num[4:8]}-{num[8:]}"]) if r.random() > .25 else num


def pan(r, surname="A"):
    return "".join(r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(3)) + r.choice("PCHFATBLJG") + surname[0].upper() + \
        f"{r.randint(0, 9999):04d}" + r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")


def gstin(r, p):
    g = r.choice(STATES) + p + str(r.randint(1, 9)) + "Z"
    return g + gstin_check_char(g)


def voter(r): return "".join(r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(3)) + f"{r.randint(0, 9999999):07d}"
def passport(r): return r.choice("ABCDEFGHJKLMNPRSTUVWY") + str(r.randint(1, 9)) + f"{r.randint(0, 99999):05d}" + str(r.randint(1, 9))


def address(r):
    city, pre, locs = r.choice(CITIES)
    loc, pin, n = r.choice(locs), pre + f"{r.randint(1, 99):03d}", r.randint(1, 240)
    return r.choice([f"No. {n}, {r.randint(1, 12)}th Cross, {loc}, {city} - {pin}",
                     f"Flat {n}B, {r.choice(['Sai', 'Lotus', 'Green'])} Apartments, {loc}, {city} {pin}",
                     f"#{n}, {r.randint(1, 9)}th Main Road, {loc}, {city}, {pin}",
                     f"H.No. {r.randint(1, 9)}-{n}-{r.randint(1, 99)}, {loc}, {city} - {pin}"])


def build(parts):
    text, ents = "", []
    for p in parts:
        if isinstance(p, str):
            text += p
        else:
            t, v = p
            ents.append({"type": t, "start": len(text), "end": len(text) + len(v), "value": v})
            text += v
    return text, ents


def loan(r, i):
    p, f = name(r), name(r)
    parts = ["LOAN APPLICATION FORM\nApplication No: LN", f"{r.randint(10**9, 10**10-1)}", "\nApplicant Name: ", ("PERSON", p),
             "\nFather's Name: ", ("PERSON", f), "\nAddress: ", ("ADDRESS", address(r)), "\nMobile: ", ("PHONE", phone(r)),
             "   Email: ", ("EMAIL", email(r, p)), "\nAadhaar: ", ("AADHAAR", aadhaar(r)), "\nPAN: ", ("PAN", pan(r, p.split()[-1]))]
    if i % 3 == 0:
        pn = pan(r, "S")
        parts += ["\nBusiness: ", COMPANIES[i % 5], "  GSTIN: ", ("GSTIN", gstin(r, pn))]
    parts += [f"\nLoan requested: Rs. {r.randint(2, 40) * 50000} for {r.choice(PURPOSES)} over {r.choice([12, 24, 36, 60])} months.\n"
              "Declaration: I, ", ("PERSON", p), ", hereby declare that the details above are true.\nRegards,\n", ("PERSON", p)]
    return build(parts)


def kyc(r, i):
    p = name(r)
    ids = [("Aadhaar number ", "AADHAAR", aadhaar(r)), ("PAN ", "PAN", pan(r, p.split()[-1])), ("Passport No. ", "PASSPORT", passport(r)),
           ("Voter ID (EPIC): ", "VOTER_ID", voter(r))]
    r.shuffle(ids)
    parts = ["KYC VERIFICATION RECORD\nCustomer: ", ("PERSON", p), f"\nDate of birth: {r.randint(1, 28):02d}/{r.randint(1, 12):02d}/{r.randint(1960, 2002)}\n",
             "Permanent address: ", ("ADDRESS", address(r)), "\n"]
    for lab, t, v in ids[:r.choice([2, 3, 4])]:
        parts += [lab, (t, v), "\n"]
    parts += ["Nominee: ", ("PERSON", name(r)), "\nContact: ", ("PHONE", phone(r)), "\nVerified by: Branch Manager ", ("PERSON", name(r))]
    return build(parts)


def ticket(r, i):
    p = name(r)
    style = i % 3
    if style == 0:     # English
        parts = [f"Ticket #TKT-{r.randint(2024, 2026)}-{r.randint(100000, 999999)}\nSubject: Unable to update KYC\nHello team, my name is ", ("PERSON", p),
                 ". My Aadhaar ", ("AADHAAR", aadhaar(r)), " is not linking with my PAN ", ("PAN", pan(r, p.split()[-1])), ". Please call me on ",
                 ("PHONE", phone(r)), " or write to ", ("EMAIL", email(r, p)), ". My address is ", ("ADDRESS", address(r)), ". Thanks."]
    elif style == 1:   # Hinglish
        parts = ["Namaste, mera naam ", ("PERSON", p), " hai. Mera Aadhaar ", ("AADHAAR", aadhaar(r)), " link nahi ho raha hai aur meri PAN ",
                 ("PAN", pan(r, p.split()[-1])), " bhi update karni hai. Aap mujhe ", ("PHONE", phone(r)), " par call karo. ",
                 ("PERSON", name(r)), " ji ne bola ki branch jaana padega. Mera address: ", ("ADDRESS", address(r))]
    else:              # Kannada-English
        parts = ["Nanna hesaru ", ("PERSON", p), ". Nanna Aadhaar number ", ("AADHAAR", aadhaar(r)), " ide, adu update maadi. Nanna mobile ",
                 ("PHONE", phone(r)), ". Nanna address ", ("ADDRESS", address(r)), " alli iddini. Dhanyavadagalu."]
    return build(parts)


def insurance(r, i):
    p, c = name(r), name(r)
    parts = [f"INSURANCE CLAIM INTAKE\nClaim No: CLM-{r.randint(2024, 2026)}-{r.randint(100000, 999999)}\nPolicy No: POL{r.randint(1000000, 9999999)}\n"
             "Policyholder: ", ("PERSON", p), "\nClaimant (", r.choice(["spouse", "son", "self"]), "): ", ("PERSON", c),
             f"\nHospital: City Care Hospital, admitted {r.randint(1, 28):02d}/{r.randint(1, 12):02d}/2026\nAddress: ", ("ADDRESS", address(r)),
             "\nContact: ", ("PHONE", phone(r)), ", ", ("EMAIL", email(r, c)), "\nAadhaar: ", ("AADHAAR", aadhaar(r)),
             f"\nBank UTR: {r.randint(10**11, 10**12-1)}\n"]
    if i % 4 == 0:
        parts += ["Passport (overseas cover): ", ("PASSPORT", passport(r)), "\n"]
    parts += ["Note: Mr. ", ("PERSON", p.split()[-1]), " requested cashless settlement."] if " " in p and "." not in p else []
    return build(parts)


def main(out="data/synthetic_docs.json"):
    r = random.Random(SEED)
    plan = [("loan_application", loan)] * 13 + [("kyc", kyc)] * 13 + [("support_ticket", ticket)] * 12 + [("insurance_claim", insurance)] * 12
    docs = []
    for idx, (dt, fn) in enumerate(plan):
        text, ents = fn(r, idx)
        docs.append({"id": f"DOC{idx + 1:03d}", "doc_type": dt, "text": text, "entities": ents})
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    json.dump(docs, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"wrote {len(docs)} docs, {sum(len(d['entities']) for d in docs)} labelled entities -> {out}")


if __name__ == "__main__":
    main()
