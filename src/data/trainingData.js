/**
 * Comprehensive Training Data for Scam Detection
 * Sourced from RBI, NPCI, CERT-In, SBI, HDFC, ICICI, and other official sources
 * 
 * This data helps the AI model distinguish between legitimate and fraudulent messages
 */

// ============================================================================
// SCAM MESSAGE EXAMPLES - Categorized by Type
// ============================================================================

export const SCAM_EXAMPLES = {
    // -------------------------------------------------------------------------
    // 1. KYC UPDATE SCAMS
    // -------------------------------------------------------------------------
    kyc_scams: [
        {
            message: "Dear customer, your KYC has expired. Update now to avoid account suspension: http://sbi-kyc-update.xyz",
            scamType: "kyc_fraud",
            channel: "sms",
            indicators: ["urgency", "fake_link", "account_suspension_threat"]
        },
        {
            message: "URGENT: Your SBI YONO account has been disabled due to incomplete KYC. Click here to reactivate: bit.ly/sbi-kyc",
            scamType: "kyc_fraud",
            channel: "sms",
            indicators: ["urgency", "fake_link", "impersonation"]
        },
        {
            message: "KYC update is due for HDFC account! Please update it by clicking http://hdfc-update.info else your account will be blocked thanks",
            scamType: "kyc_fraud",
            channel: "sms",
            indicators: ["urgency", "fake_link", "account_suspension_threat", "grammar_errors"]
        },
        {
            message: "Dear valued customer, Your Airtel SIM KYC is not complete. Your number will be disconnected in 24 hours. Update now: wa.me/scammer",
            scamType: "kyc_fraud",
            channel: "sms",
            indicators: ["urgency", "fake_link", "disconnection_threat"]
        },
        {
            message: "Your Pan Card is not linked with your bank account. Please update immediately to continue using banking services. Click: pan-link.in",
            scamType: "kyc_fraud",
            channel: "sms",
            indicators: ["urgency", "fake_link", "document_link_scam"]
        },
        {
            message: "ICICI Bank: Your account will be suspended within 24 hours due to pending KYC verification. Complete now: icici-secureverify.com",
            scamType: "kyc_fraud",
            channel: "sms",
            indicators: ["urgency", "fake_link", "impersonation", "time_pressure"]
        }
    ],

    // -------------------------------------------------------------------------
    // 2. UPI AND BANKING FRAUD
    // -------------------------------------------------------------------------
    upi_banking_fraud: [
        {
            message: "INR 25,000 debited from your account. If not done by you, report here: http://sbi-dispute.xyz to block further transactions",
            scamType: "upi_fraud",
            channel: "sms",
            indicators: ["fake_transaction", "urgency", "fake_link"]
        },
        {
            message: "You have received ₹15,000 on UPI. To accept payment, enter PIN. Transaction ID: TXN123456789",
            scamType: "upi_fraud",
            channel: "sms",
            indicators: ["pin_request", "fake_credit_notification"]
        },
        {
            message: "Dear Customer, ₹50,000 has been credited to your account by mistake. Please return via UPI to 9876543210@ybl immediately",
            scamType: "upi_fraud",
            channel: "whatsapp",
            indicators: ["accidental_credit_scam", "urgency", "upi_request"]
        },
        {
            message: "Your UPI PIN will expire today. Reset immediately by clicking: upi-reset-secure.in to avoid transaction failure",
            scamType: "upi_fraud",
            channel: "sms",
            indicators: ["urgency", "fake_link", "pin_expiry_scam"]
        },
        {
            message: "Scan this QR code to receive ₹5000 cashback reward from Paytm: [QR CODE IMAGE]",
            scamType: "upi_fraud",
            channel: "whatsapp",
            indicators: ["qr_code_scam", "too_good_to_be_true"]
        },
        {
            message: "ALERT: There is suspicious activity on your account ending 4521. Contact immediately: 1800-XXX-XXXX or your account will be frozen",
            scamType: "banking_fraud",
            channel: "sms",
            indicators: ["urgency", "fear_tactic", "fake_helpline"]
        },
        {
            message: "Your HDFC NetBanking Account will be blocked today. Please click on the link and update your PAN CARD Number Immediately: hdfc-panupdate.com",
            scamType: "banking_fraud",
            channel: "sms",
            indicators: ["urgency", "fake_link", "impersonation"]
        }
    ],

    // -------------------------------------------------------------------------
    // 3. LOTTERY AND PRIZE SCAMS
    // -------------------------------------------------------------------------
    lottery_scams: [
        {
            message: "Congratulations! You've won ₹25 Lakhs in the International WhatsApp Lottery! Contact Mr. Sharma at +91-9876543210 to claim. Processing fee: ₹5000",
            scamType: "lottery_scam",
            channel: "whatsapp",
            indicators: ["lottery_win", "processing_fee", "too_good_to_be_true"]
        },
        {
            message: "DEAR WINNER: Your mobile number has been selected for ₹50,00,000 in RBI Bumper Draw. Send ₹10,000 for tax clearance to claim prize.",
            scamType: "lottery_scam",
            channel: "sms",
            indicators: ["lottery_win", "advance_fee", "rbi_impersonation"]
        },
        {
            message: "You have won a new iPhone 15 Pro from Flipkart Lucky Draw! Claim now by paying delivery charges of ₹999: flipkart-prize.com",
            scamType: "lottery_scam",
            channel: "sms",
            indicators: ["prize_win", "advance_fee", "fake_link"]
        },
        {
            message: "Amazon Lucky Winner!! You have won ₹10,00,000. To claim your prize, contact our agent and pay registration fee: +91-8765432109",
            scamType: "lottery_scam",
            channel: "whatsapp",
            indicators: ["lottery_win", "registration_fee", "impersonation"]
        },
        {
            message: "BBC WORLD SERVICE PROMO. Your email has won £500,000 GBP. Reply with your name, address and bank details to claim.",
            scamType: "lottery_scam",
            channel: "email",
            indicators: ["lottery_win", "personal_info_request", "bank_details_request"]
        }
    ],

    // -------------------------------------------------------------------------
    // 4. JOB OFFER SCAMS
    // -------------------------------------------------------------------------
    job_scams: [
        {
            message: "Congrats! You're selected for Amazon WFH job. ₹50,000/month salary. Pay ₹7500 security deposit to confirm. Limited seats!",
            scamType: "job_scam",
            channel: "whatsapp",
            indicators: ["job_offer", "security_deposit", "urgency", "wfh_scam"]
        },
        {
            message: "TATA Company is hiring. Daily income ₹2000-5000. Simple data entry work. No experience required. Contact: wa.me/scammer",
            scamType: "job_scam",
            channel: "sms",
            indicators: ["job_offer", "unrealistic_income", "no_experience"]
        },
        {
            message: "Dear Candidate, Your resume has been shortlisted for Google. Please deposit ₹15,000 for background verification. Refundable with first salary.",
            scamType: "job_scam",
            channel: "email",
            indicators: ["job_offer", "verification_fee", "impersonation"]
        },
        {
            message: "Urgent requirement! Fresher/Experienced. Earn ₹1 Lakh/month from home. Part time data entry. Contact HR: +91-9999888877",
            scamType: "job_scam",
            channel: "whatsapp",
            indicators: ["job_offer", "unrealistic_income", "urgency"]
        },
        {
            message: "You are selected for Instagram/YouTube review job. Earn ₹500-1000 per review. Join Telegram: t.me/fake_job_group",
            scamType: "job_scam",
            channel: "whatsapp",
            indicators: ["job_offer", "task_scam", "telegram_redirect"]
        }
    ],

    // -------------------------------------------------------------------------
    // 5. DIGITAL ARREST / IMPERSONATION SCAMS
    // -------------------------------------------------------------------------
    impersonation_scams: [
        {
            message: "This is CBI. Your Aadhaar is linked to money laundering case. You are under DIGITAL ARREST. Transfer ₹5 Lakh or face immediate arrest.",
            scamType: "digital_arrest",
            channel: "call",
            indicators: ["authority_impersonation", "digital_arrest", "fear_tactic", "immediate_payment"]
        },
        {
            message: "Mumbai Police Cyber Cell: A case is registered against you. Your bank accounts will be frozen. Contact immediately to resolve: +91-XXXXXXXXXX",
            scamType: "authority_impersonation",
            channel: "call",
            indicators: ["police_impersonation", "fear_tactic", "urgency"]
        },
        {
            message: "INCOME TAX DEPARTMENT: You have pending tax of ₹2,50,000. Pay within 2 hours to avoid property seizure. UPI: taxclearance@paytm",
            scamType: "authority_impersonation",
            channel: "sms",
            indicators: ["it_impersonation", "urgency", "upi_request", "fear_tactic"]
        },
        {
            message: "Your son/daughter has been arrested for drug possession. Send ₹2 Lakh immediately for bail. Police station: 9876543210",
            scamType: "emergency_scam",
            channel: "call",
            indicators: ["family_emergency", "fear_tactic", "immediate_payment"]
        },
        {
            message: "RBI Alert: Your account is being used for fraudulent transactions. Verify ownership by transferring ₹10,000 to secure account: rbi@sbi",
            scamType: "rbi_impersonation",
            channel: "sms",
            indicators: ["rbi_impersonation", "secure_account_scam", "fear_tactic"]
        },
        {
            message: "Customs Department: A parcel in your name contains illegal items. Pay ₹50,000 fine to avoid arrest. Case No: CD/2024/XXX",
            scamType: "authority_impersonation",
            channel: "call",
            indicators: ["customs_impersonation", "fear_tactic", "advance_fee"]
        }
    ],

    // -------------------------------------------------------------------------
    // 6. INVESTMENT AND CRYPTO SCAMS
    // -------------------------------------------------------------------------
    investment_scams: [
        {
            message: "Join our stock trading group! 100% guaranteed returns. Invest ₹10,000 get ₹50,000 in 7 days. WhatsApp: +91-XXXXXXXXXX",
            scamType: "investment_scam",
            channel: "whatsapp",
            indicators: ["guaranteed_returns", "unrealistic_profit", "urgency"]
        },
        {
            message: "Exclusive Bitcoin opportunity! Double your investment in 48 hours. Minimum ₹25,000. Act now before it's gone!",
            scamType: "crypto_scam",
            channel: "whatsapp",
            indicators: ["crypto_scam", "guaranteed_returns", "urgency"]
        },
        {
            message: "Hi, I'm Sarah. I made ₹15 Lakhs last month trading forex. Want me to teach you? Let's connect on WhatsApp.",
            scamType: "pig_butchering",
            channel: "whatsapp",
            indicators: ["stranger_message", "investment_offer", "relationship_building"]
        },
        {
            message: "Wrong number? Sorry! By the way, what do you do? I'm a financial advisor and I help people grow their money...",
            scamType: "pig_butchering",
            channel: "whatsapp",
            indicators: ["wrong_number_opening", "investment_topic", "relationship_building"]
        },
        {
            message: "IPO Alert! Reliance new share at ₹10. Will reach ₹500 in 1 month. Limited time offer. Invest now: ipo-invest.com",
            scamType: "investment_scam",
            channel: "sms",
            indicators: ["fake_ipo", "guaranteed_returns", "fake_link"]
        },
        {
            message: "MLM opportunity! Build passive income. Refer 5 friends and earn ₹1 Lakh/month. Join our network: wa.me/mlmscam",
            scamType: "mlm_scam",
            channel: "whatsapp",
            indicators: ["mlm_scheme", "referral_pyramid", "passive_income_promise"]
        }
    ],

    // -------------------------------------------------------------------------
    // 7. ROMANCE SCAMS
    // -------------------------------------------------------------------------
    romance_scams: [
        {
            message: "Hi! I found your profile on matrimonial site. I'm a successful businessman in Dubai. Let's get to know each other on WhatsApp.",
            scamType: "romance_scam",
            channel: "matrimonial",
            indicators: ["stranger_contact", "relationship_building", "platform_switch"]
        },
        {
            message: "I've been talking to you for 2 months and I feel we have a connection. I need ₹50,000 urgently for my mother's surgery. Will pay back.",
            scamType: "romance_scam",
            channel: "whatsapp",
            indicators: ["emotional_manipulation", "emergency_money_request", "relationship_exploitation"]
        },
        {
            message: "I'm a US Army soldier stationed abroad. I have gold bars worth $2 million I want to send to India. Just need ₹1 Lakh for shipping.",
            scamType: "romance_scam",
            channel: "whatsapp",
            indicators: ["military_romance_scam", "gold_shipping_scam", "advance_fee"]
        }
    ],

    // -------------------------------------------------------------------------
    // 8. DELIVERY AND PACKAGE SCAMS
    // -------------------------------------------------------------------------
    delivery_scams: [
        {
            message: "India Post: Your package has arrived at our facility. Update address within 12 hours or it will be returned: indiapost-delivery.com",
            scamType: "delivery_scam",
            channel: "sms",
            indicators: ["fake_delivery", "urgency", "fake_link"]
        },
        {
            message: "FedEx: Unable to deliver your parcel. Pay customs duty of ₹2,500 to release: fedex-customs.in",
            scamType: "delivery_scam",
            channel: "sms",
            indicators: ["fake_delivery", "customs_fee", "fake_link"]
        },
        {
            message: "Your Amazon order has been held at customs. Pay ₹899 handling charges: amazon-customs-payment.com",
            scamType: "delivery_scam",
            channel: "sms",
            indicators: ["fake_delivery", "handling_charges", "fake_link", "impersonation"]
        }
    ],

    // -------------------------------------------------------------------------
    // 9. TECH SUPPORT SCAMS
    // -------------------------------------------------------------------------
    tech_support_scams: [
        {
            message: "Microsoft Alert: Your computer has a virus! Call immediately: 1800-XXX-XXXX to prevent data loss.",
            scamType: "tech_support_scam",
            channel: "popup",
            indicators: ["fake_virus_alert", "urgency", "fake_helpline"]
        },
        {
            message: "Your WhatsApp will expire tomorrow. Verify account now or lose access: whatsapp-verify.com",
            scamType: "tech_support_scam",
            channel: "whatsapp",
            indicators: ["fake_expiry", "urgency", "fake_link"]
        },
        {
            message: "Install AnyDesk app urgently. Our bank executive will help fix your netbanking issue. App link: anydesk.com",
            scamType: "remote_access_scam",
            channel: "call",
            indicators: ["remote_access_request", "bank_impersonation", "urgency"]
        }
    ],

    // -------------------------------------------------------------------------
    // 10. TRAFFIC AND GOVERNMENT SCAMS
    // -------------------------------------------------------------------------
    government_scams: [
        {
            message: "Traffic Police: You have unpaid challan of ₹2,500. Pay immediately to avoid vehicle seizure: traffic-echallan.xyz",
            scamType: "traffic_scam",
            channel: "sms",
            indicators: ["fake_challan", "urgency", "fake_link"]
        },
        {
            message: "Your driving license is about to expire. Renew online now to avoid penalty: dl-renewal-india.com",
            scamType: "government_scam",
            channel: "sms",
            indicators: ["fake_renewal", "fake_link"]
        },
        {
            message: "PM-KISAN: Your subsidy of ₹6000 is pending. Update bank details to receive: pmkisan-update.in",
            scamType: "government_scam",
            channel: "sms",
            indicators: ["government_scheme_scam", "bank_details_request", "fake_link"]
        },
        {
            message: "Aadhaar Update Required: Your Aadhaar will be deactivated. Update biometrics at: uidai-update.org",
            scamType: "government_scam",
            channel: "sms",
            indicators: ["aadhaar_scam", "fake_link", "deactivation_threat"]
        }
    ],

    // -------------------------------------------------------------------------
    // 11. OTP AND CALL MERGING SCAMS
    // -------------------------------------------------------------------------
    otp_scams: [
        {
            message: "Hi, I accidentally sent OTP to your number. Can you please share the 6-digit code you received? Sorry for the trouble.",
            scamType: "otp_theft",
            channel: "whatsapp",
            indicators: ["otp_request", "social_engineering"]
        },
        {
            message: "OLX: Hi, I'm interested in your product. Can you share the OTP I sent to verify you're genuine seller?",
            scamType: "otp_theft",
            channel: "whatsapp",
            indicators: ["otp_request", "olx_scam", "verification_excuse"]
        },
        {
            message: "Bank Executive: For security verification, please share the OTP sent to your number. This is routine procedure.",
            scamType: "otp_theft",
            channel: "call",
            indicators: ["otp_request", "bank_impersonation"]
        }
    ],

    // -------------------------------------------------------------------------
    // 12. LOAN SCAMS
    // -------------------------------------------------------------------------
    loan_scams: [
        {
            message: "Instant Loan ₹5 Lakh at 0% interest! No documents required. Apply now: quick-loan-india.com. Limited offer!",
            scamType: "loan_scam",
            channel: "sms",
            indicators: ["unrealistic_terms", "no_documents", "urgency", "fake_link"]
        },
        {
            message: "Your loan of ₹3 Lakh is PRE-APPROVED! Pay ₹3,500 processing fee to receive funds in 2 hours.",
            scamType: "loan_scam",
            channel: "sms",
            indicators: ["pre_approved_loan", "processing_fee"]
        },
        {
            message: "RBI CERTIFIED LOAN: Get ₹10 Lakh personal loan. Only ₹5,000 insurance premium. 100% guaranteed approval.",
            scamType: "loan_scam",
            channel: "sms",
            indicators: ["rbi_certification_claim", "advance_fee", "guaranteed_approval"]
        }
    ],

    // -------------------------------------------------------------------------
    // 13. ELECTRICITY AND UTILITY SCAMS
    // -------------------------------------------------------------------------
    utility_scams: [
        {
            message: "URGENT: Your electricity will be disconnected today due to pending bill of ₹3,456. Pay now: electricity-bill-pay.in",
            scamType: "utility_scam",
            channel: "sms",
            indicators: ["disconnection_threat", "urgency", "fake_link"]
        },
        {
            message: "BSES Alert: Bill overdue. Power cut scheduled in 2 hours. Update payment: bses-quickpay.com",
            scamType: "utility_scam",
            channel: "sms",
            indicators: ["disconnection_threat", "urgency", "fake_link", "impersonation"]
        }
    ]
};

// ============================================================================
// LEGITIMATE MESSAGE EXAMPLES - For Training Model to Recognize Safe Messages
// ============================================================================

export const LEGITIMATE_EXAMPLES = {
    // -------------------------------------------------------------------------
    // 1. GENUINE BANK TRANSACTION ALERTS
    // -------------------------------------------------------------------------
    bank_transactions: [
        {
            message: "INR 5,000.00 debited from A/c XX6789 on 05-FEB-26 to VPA john@okaxis (UPI Ref: 503421789012). Avl Bal: INR 45,230.50 -SBI",
            isScam: false,
            channel: "sms",
            sender: "VM-SBIINB",
            indicators: ["official_sender_id", "transaction_details", "proper_format"]
        },
        {
            message: "Dear Customer, Rs.2,500.00 is credited to your A/c XXXX1234 by NEFT from AXIS BANK. Available balance: Rs.32,450.00 -HDFC Bank",
            isScam: false,
            channel: "sms",
            sender: "VK-HDFCBK",
            indicators: ["official_sender_id", "credit_notification", "proper_format"]
        },
        {
            message: "You've spent INR 899.00 on your ICICI Card XX4521 at AMAZON RETAIL on 05-FEB at 14:30. Call 1800-XXX-XXXX if not you.",
            isScam: false,
            channel: "sms",
            sender: "TM-ICICIB",
            indicators: ["official_sender_id", "transaction_alert", "proper_format"]
        },
        {
            message: "UPI transaction of Rs.150.00 successful to swiggy@paytm from your KOTAK Bank A/c XX7890. Ref: 503412345678.",
            isScam: false,
            channel: "sms",
            sender: "AD-KOTAKB",
            indicators: ["official_sender_id", "upi_confirmation", "proper_format"]
        },
        {
            message: "Your IMPS transfer of Rs.10,000 to A/c ending 5678 (AXIS Bank) is successful. IMPS Ref No: 503498765432. -PNB",
            isScam: false,
            channel: "sms",
            sender: "VM-PNBSMS",
            indicators: ["official_sender_id", "imps_confirmation", "proper_format"]
        }
    ],

    // -------------------------------------------------------------------------
    // 2. GENUINE OTP MESSAGES
    // -------------------------------------------------------------------------
    otp_messages: [
        {
            message: "Your OTP for SBI Net Banking login is 482956. Valid for 3 mins. Do NOT share with anyone. SBI never asks for OTP.",
            isScam: false,
            channel: "sms",
            sender: "VM-SBIINB",
            indicators: ["official_sender_id", "security_warning", "time_validity"]
        },
        {
            message: "Dear Customer, 847291 is your OTP for HDFC Bank transaction of Rs.5,000. Valid for 10 mins. Never share OTP.",
            isScam: false,
            channel: "sms",
            sender: "VK-HDFCBK",
            indicators: ["official_sender_id", "transaction_otp", "security_warning"]
        },
        {
            message: "Your OTP for Paytm is 629481. It is valid for 10 minutes. Do not share this OTP with anyone. - Paytm",
            isScam: false,
            channel: "sms",
            sender: "AM-PAYTMB",
            indicators: ["official_sender_id", "proper_format", "security_warning"]
        },
        {
            message: "123456 is your verification code for Amazon. It expires in 10 minutes. Don't share this code with anyone.",
            isScam: false,
            channel: "sms",
            sender: "AX-AMAZON",
            indicators: ["official_sender_id", "verification_code", "security_warning"]
        }
    ],

    // -------------------------------------------------------------------------
    // 3. GENUINE SERVICE NOTIFICATIONS
    // -------------------------------------------------------------------------
    service_notifications: [
        {
            message: "Your Airtel recharge of Rs.299 is successful. Talk time: Unlimited. Data: 2GB/day valid for 28 days. -Airtel",
            isScam: false,
            channel: "sms",
            sender: "AM-AIRTEL",
            indicators: ["official_sender_id", "recharge_confirmation", "plan_details"]
        },
        {
            message: "Your order #OD42891023 has been shipped! Track: amzn.in/d/aBcDeFg. Delivery by 7 Feb. -Amazon",
            isScam: false,
            channel: "sms",
            sender: "AX-AMAZON",
            indicators: ["official_sender_id", "order_tracking", "official_link"]
        },
        {
            message: "Your Swiggy order from Domino's Pizza is out for delivery! Your OPT is 2847. Track: swiggy.com/track",
            isScam: false,
            channel: "sms",
            sender: "CP-SWIGGY",
            indicators: ["official_sender_id", "delivery_update", "official_link"]
        },
        {
            message: "Your IRCTC ticket PNR: 4521789632 is CONFIRMED. Train: 12302, 05-Feb, Coach B1, Seat 45. Have a safe journey!",
            isScam: false,
            channel: "sms",
            sender: "AD-IRCTCS",
            indicators: ["official_sender_id", "booking_confirmation", "specific_details"]
        }
    ],

    // -------------------------------------------------------------------------
    // 4. GENUINE BANK NOTIFICATIONS
    // -------------------------------------------------------------------------
    bank_notifications: [
        {
            message: "Dear Customer, Your SBI Credit Card statement for Jan 2026 is ready. Total Due: Rs.15,432. Pay by 15-Feb. Visit sbi.co.in",
            isScam: false,
            channel: "sms",
            sender: "VM-SBICRD",
            indicators: ["official_sender_id", "statement_notification", "official_website"]
        },
        {
            message: "Your Fixed Deposit of Rs.1,00,000 (FD No: 12345678) will mature on 15-Feb-2026. Visit branch or net banking to renew. -HDFC Bank",
            isScam: false,
            channel: "sms",
            sender: "VK-HDFCBK",
            indicators: ["official_sender_id", "maturity_reminder", "no_link"]
        },
        {
            message: "Your home loan EMI of Rs.28,500 has been debited successfully for Feb 2026. Outstanding: Rs.18,45,230. -ICICI Bank",
            isScam: false,
            channel: "sms",
            sender: "TM-ICICIB",
            indicators: ["official_sender_id", "emi_debit", "loan_details"]
        },
        {
            message: "Reminder: Your HDFC Credit Card payment of Rs.8,500 is due on 10-Feb-2026. Pay via NetBanking or HDFC Bank app.",
            isScam: false,
            channel: "sms",
            sender: "VK-HDFCBK",
            indicators: ["official_sender_id", "payment_reminder", "no_external_link"]
        }
    ],

    // -------------------------------------------------------------------------
    // 5. GENUINE GOVERNMENT NOTIFICATIONS
    // -------------------------------------------------------------------------
    government_notifications: [
        {
            message: "Your income tax return for AY 2025-26 has been processed. Refund of Rs.12,500 will be credited to bank a/c. -Income Tax Dept",
            isScam: false,
            channel: "sms",
            sender: "AD-ITDEFL",
            indicators: ["official_sender_id", "refund_notification", "no_link"]
        },
        {
            message: "Your PM-KISAN installment of Rs.2000 has been credited to your bank account XX1234 on 01-Feb-2026. -PFMS",
            isScam: false,
            channel: "sms",
            sender: "AM-PFMSMS",
            indicators: ["official_sender_id", "credit_confirmation", "scheme_payment"]
        },
        {
            message: "Your Aadhaar OTP is 482918. Valid for 10 mins. Never share OTP with anyone. -UIDAI",
            isScam: false,
            channel: "sms",
            sender: "AM-UIDAI",
            indicators: ["official_sender_id", "aadhaar_otp", "security_warning"]
        },
        {
            message: "Your vehicle RC renewal application has been submitted. Application No: DL-2026-123456. Track at parivahan.gov.in -RTO",
            isScam: false,
            channel: "sms",
            sender: "TD-RTODLH",
            indicators: ["official_sender_id", "application_confirmation", "official_website"]
        }
    ],

    // -------------------------------------------------------------------------
    // 6. GENUINE PROMOTIONAL MESSAGES (From Real Brands)
    // -------------------------------------------------------------------------
    promotional_messages: [
        {
            message: "Flat 50% OFF on all electronics this weekend! Shop now at Flipkart. T&C apply. To opt out, reply STOP.",
            isScam: false,
            channel: "sms",
            sender: "HP-FLIPKT",
            indicators: ["official_sender_id", "marketing_message", "opt_out_option"]
        },
        {
            message: "Get 20% cashback up to Rs.100 on your next Swiggy order using HDFC Bank cards. Order now!",
            isScam: false,
            channel: "sms",
            sender: "HP-SWIGGY",
            indicators: ["official_sender_id", "cashback_offer", "partner_promotion"]
        },
        {
            message: "Your BigBasket order is arriving today between 4-6 PM. Stay available. Track: bigbasket.com/track",
            isScam: false,
            channel: "sms",
            sender: "BM-BIGBAS",
            indicators: ["official_sender_id", "delivery_update", "official_link"]
        }
    ],

    // -------------------------------------------------------------------------
    // 7. GENUINE SALARY AND BUSINESS MESSAGES
    // -------------------------------------------------------------------------
    salary_business: [
        {
            message: "Salary credited: Rs.75,000.00 to A/c XX1234 on 01-Feb-2026 by NEFT from ABC TECHNOLOGIES PVT LTD. -Axis Bank",
            isScam: false,
            channel: "sms",
            sender: "AD-AXISBK",
            indicators: ["official_sender_id", "salary_credit", "employer_name"]
        },
        {
            message: "Dear Employer, EPF contribution of Rs.12,500 for Jan 2026 has been received. Member A/c: XXXX12345. -EPFO",
            isScam: false,
            channel: "sms",
            sender: "AM-EPFIND",
            indicators: ["official_sender_id", "epf_contribution", "member_details"]
        }
    ],

    // -------------------------------------------------------------------------
    // 8. GENUINE PERSONAL COMMUNICATIONS
    // -------------------------------------------------------------------------
    personal_messages: [
        {
            message: "Hi, I'll be 10 mins late for our meeting. Traffic is bad today. See you soon!",
            isScam: false,
            channel: "whatsapp",
            indicators: ["personal_communication", "no_links", "normal_language"]
        },
        {
            message: "Don't forget to pick up milk on your way home. Also, mom called - call her back.",
            isScam: false,
            channel: "whatsapp",
            indicators: ["family_communication", "no_links", "normal_content"]
        },
        {
            message: "Happy Birthday! Wishing you a wonderful year ahead. Let's catch up over dinner this weekend?",
            isScam: false,
            channel: "whatsapp",
            indicators: ["birthday_wish", "personal_message", "no_requests"]
        },
        {
            message: "Meeting rescheduled to 3 PM tomorrow. Please confirm your availability. - HR Team",
            isScam: false,
            channel: "email",
            indicators: ["work_communication", "meeting_update", "no_suspicious_content"]
        }
    ]
};

// ============================================================================
// SCAM INDICATORS AND PATTERNS
// ============================================================================

export const SCAM_INDICATORS = {
    urgency_phrases: [
        "act now", "immediately", "urgent", "within 24 hours", "today only",
        "limited time", "expires soon", "last chance", "don't delay",
        "instant", "ASAP", "right now", "before it's too late",
        "अभी करें", "तुरंत", "जल्दी"
    ],

    threat_phrases: [
        "account will be blocked", "will be suspended", "legal action",
        "police complaint", "arrest warrant", "court case", "penalty",
        "frozen account", "deactivated", "seized", "imprisoned",
        "खाता बंद", "गिरफ्तारी", "जुर्माना"
    ],

    too_good_to_be_true: [
        "won lottery", "free gift", "guaranteed returns", "100% profit",
        "double your money", "no risk", "secret method", "easy money",
        "lakhs", "crores", "million dollars", "jackpot",
        "लॉटरी जीते", "मुफ्त उपहार"
    ],

    request_patterns: [
        "share OTP", "enter PIN", "click link", "download app",
        "transfer money", "pay fee", "send details", "provide password",
        "verify account", "update KYC", "confirm identity",
        "OTP बताएं", "पैसे भेजें"
    ],

    suspicious_domains: [
        ".xyz", ".info", ".top", ".click", ".link", ".online",
        "bit.ly", "tinyurl", "short.url", "wa.me",
        "-update", "-verify", "-secure", "-official",
        "free-", "win-", "claim-"
    ],

    impersonation_keywords: [
        "RBI official", "bank manager", "police officer", "CBI agent",
        "customs officer", "income tax officer", "government official",
        "Microsoft support", "Amazon representative",
        "सरकारी अधिकारी", "बैंक मैनेजर"
    ],

    payment_requests: [
        "UPI ID", "bank account", "Google Pay", "PhonePe", "Paytm",
        "credit card", "debit card", "crypto wallet", "gift card",
        "Western Union", "processing fee", "advance payment",
        "registration fee", "security deposit"
    ]
};

// ============================================================================
// LEGITIMATE MESSAGE PATTERNS
// ============================================================================

export const LEGITIMATE_PATTERNS = {
    official_sender_ids: [
        "VM-SBIINB", "VK-HDFCBK", "TM-ICICIB", "AD-AXISBK", "VM-PNBSMS",
        "AD-KOTAKB", "AM-PAYTMB", "AX-AMAZON", "CP-SWIGGY", "HP-FLIPKT",
        "AM-AIRTEL", "BM-JIONET", "AD-IRCTCS", "AM-UIDAI", "AM-PFMSMS"
    ],

    secure_domains: [
        "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
        "paytm.com", "amazon.in", "flipkart.com", "swiggy.com",
        "incometax.gov.in", "uidai.gov.in", "parivahan.gov.in",
        "irctc.co.in", "npci.org.in"
    ],

    genuine_message_traits: [
        "Official sender ID format (XX-BANKNAME)",
        "No requests for OTP, PIN, or password",
        "No external links for sensitive operations",
        "Proper grammar and spelling",
        "Specific transaction/reference details",
        "No emotional manipulation or threats",
        "Clear opt-out options for marketing"
    ]
};

// ============================================================================
// CHANNEL-SPECIFIC PATTERNS
// ============================================================================

export const CHANNEL_PATTERNS = {
    sms: {
        scam_indicators: [
            "Sender is 10-digit mobile number (not alphanumeric ID)",
            "Contains shortened/suspicious URLs",
            "Requests immediate action",
            "Asks for sensitive information"
        ],
        legitimate_indicators: [
            "6-character alphanumeric sender ID",
            "Format: XY-ABCDE (e.g., TM-HDFCBK)",
            "Contains transaction reference numbers",
            "No requests for sensitive data"
        ]
    },
    whatsapp: {
        scam_indicators: [
            "Message from unknown number",
            "Added to unknown groups",
            "Investment/job offers from strangers",
            "Requests to download apps or click links"
        ],
        legitimate_indicators: [
            "Known contacts only",
            "Business accounts with verified badge",
            "No unsolicited money requests"
        ]
    },
    call: {
        scam_indicators: [
            "Claims to be from RBI/Police/CBI",
            "Demands immediate payment",
            "Threatens arrest or legal action",
            "Asks to install remote access apps",
            "Requests OTP during call"
        ],
        legitimate_indicators: [
            "Called from official bank number",
            "Can verify by calling back on official number",
            "Never asks for OTP or PIN"
        ]
    },
    email: {
        scam_indicators: [
            "Sender domain doesn't match company",
            "Generic salutation (Dear Customer)",
            "Grammar and spelling errors",
            "Suspicious attachments",
            "Urgency and threats"
        ],
        legitimate_indicators: [
            "From official company domain",
            "Personalized with your name",
            "No suspicious attachments",
            "Professional formatting"
        ]
    }
};

export default {
    SCAM_EXAMPLES,
    LEGITIMATE_EXAMPLES,
    SCAM_INDICATORS,
    LEGITIMATE_PATTERNS,
    CHANNEL_PATTERNS
};
