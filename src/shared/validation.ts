import { z } from 'zod';
import {
  Candidate,
  CandidateDocument,
  DOCUMENT_CATEGORIES,
  ONBOARDING_STATUSES,
  REQUIRED_DOCUMENT_CATEGORIES,
} from './types.ts';

export const loginSchema = z.object({
  identifier: z.string().trim().min(3, 'Enter your Login ID or Email').max(200),
  password: z.string().min(6, 'Password must be at least 6 characters').max(128),
});

export const verify2FASchema = z.object({
  challengeToken: z.string().min(10),
  code: z.string().trim().regex(/^\d{6}$/, 'Enter a valid 6-digit 2FA code'),
});

export const createCandidateSchema = z.object({
  fullName: z.string().trim().min(2, 'Full name is required').max(120),
  email: z.string().trim().email('Valid email address is required').max(200),
  mobile: z
    .string()
    .trim()
    .regex(/^[+]?[0-9\s-]{8,18}$/, 'Enter a valid mobile number'),
  position: z.string().trim().min(2, 'Position applied for is required').max(120),
  department: z.string().trim().min(2, 'Department is required').max(80),
  joiningDate: z.string().trim().min(4, 'Joining date is required').max(30),
  assignedRecruiterId: z.string().trim().min(1, 'Assigned recruiter is required').max(128),
  isDemo: z.boolean().optional(),
});

export const personalInfoSchema = z.object({
  fullName: z.string().trim().min(2, 'Full name is required').max(120),
  dateOfBirth: z.string().trim().min(4, 'Date of birth is required').max(30),
  gender: z.enum(['Male', 'Female', 'Other', 'Prefer not to say'], {
    message: 'Select gender',
  }),
  mobileNumber: z
    .string()
    .trim()
    .regex(/^[+]?[0-9\s-]{8,18}$/, 'Enter a valid mobile number'),
  email: z.string().trim().email('Valid email is required').max(200),
  maritalStatus: z.enum(['Single', 'Married', 'Divorced', 'Widowed'], {
    message: 'Select marital status',
  }),
});

export const addressInfoSchema = z.object({
  currentAddress: z.string().trim().min(5, 'Current address is required').max(500),
  permanentAddress: z.string().trim().min(5, 'Permanent address is required').max(500),
  sameAsCurrent: z.boolean(),
  city: z.string().trim().min(2, 'City is required').max(100),
  state: z.string().trim().min(2, 'State is required').max(100),
  pinCode: z
    .string()
    .trim()
    .regex(/^[1-9][0-9]{5}$/, 'Enter a valid 6-digit Indian PIN code'),
});

export const familyInfoSchema = z.object({
  fatherName: z.string().trim().min(2, "Father's name is required").max(120),
  motherName: z.string().trim().min(2, "Mother's name is required").max(120),
  spouseName: z.string().trim().max(120).optional().default(''),
  emergencyContactName: z
    .string()
    .trim()
    .min(2, 'Emergency contact name is required')
    .max(120),
  emergencyContactRelation: z
    .string()
    .trim()
    .min(2, 'Emergency contact relationship is required')
    .max(60),
  emergencyContactPhone: z
    .string()
    .trim()
    .regex(/^[+]?[0-9\s-]{8,18}$/, 'Enter a valid emergency contact phone'),
});

export const educationInfoSchema = z.object({
  highestQualification: z.string().trim().min(2, 'Highest qualification is required').max(120),
  collegeUniversity: z.string().trim().min(2, 'College / University is required').max(200),
  passingYear: z
    .string()
    .trim()
    .regex(/^(19|20)\d{2}$/, 'Enter a valid 4-digit passing year'),
  percentageOrCgpa: z.string().trim().min(1, 'Percentage or CGPA is required').max(30),
});

export const employmentInfoSchema = z
  .object({
    isFresher: z.boolean(),
    previousCompany: z.string().trim().max(150).optional().default(''),
    previousDesignation: z.string().trim().max(120).optional().default(''),
    previousExperience: z.string().trim().max(60).optional().default(''),
    lastWorkingDate: z.string().trim().max(30).optional().default(''),
    previousSalary: z.string().trim().max(60).optional().default(''),
  })
  .superRefine((val, ctx) => {
    if (!val.isFresher) {
      if (!val.previousCompany || val.previousCompany.length < 2) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['previousCompany'],
          message: 'Previous company is required for experienced candidates',
        });
      }
      if (!val.previousDesignation || val.previousDesignation.length < 2) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['previousDesignation'],
          message: 'Previous designation is required',
        });
      }
      if (!val.previousExperience || val.previousExperience.length < 1) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['previousExperience'],
          message: 'Total experience is required',
        });
      }
      if (!val.lastWorkingDate || val.lastWorkingDate.length < 4) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['lastWorkingDate'],
          message: 'Last working date is required',
        });
      }
    }
  });

export const bankDetailsSchema = z
  .object({
    accountHolderName: z.string().trim().min(2, 'Account holder name is required').max(120),
    bankName: z.string().trim().min(2, 'Bank name is required').max(120),
    accountNumber: z
      .string()
      .trim()
      .regex(/^\d{9,18}$/, 'Account number must be 9 to 18 digits'),
    confirmAccountNumber: z.string().trim().optional(),
    ifscCode: z
      .string()
      .trim()
      .toUpperCase()
      .regex(/^[A-Z]{4}0[A-Z0-9]{6}$/, 'Enter a valid 11-character IFSC code (e.g. HDFC0001234)'),
  })
  .superRefine((val, ctx) => {
    if (val.confirmAccountNumber !== undefined && val.confirmAccountNumber !== val.accountNumber) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['confirmAccountNumber'],
        message: 'Account numbers do not match',
      });
    }
  });

export const declarationSchema = z.object({
  accepted: z.literal(true, {
    message: 'You must accept the declaration and consent terms before submitting',
  }),
  digitalSignature: z
    .string()
    .trim()
    .min(2, 'Type your full name as your digital signature')
    .max(120),
});

export const statusUpdateSchema = z.object({
  status: z.enum(ONBOARDING_STATUSES),
  note: z.string().trim().max(1000).optional(),
});

export const documentCategorySchema = z.enum(DOCUMENT_CATEGORIES);

export const createStaffSchema = z.object({
  fullName: z.string().trim().min(2, 'Full name is required').max(120),
  email: z.string().trim().email('Valid email is required').max(200),
  role: z.enum(['SUPER_ADMIN', 'ADMIN', 'HR']),
  department: z.string().trim().min(2, 'Department is required').max(80),
  loginId: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9_-]{4,32}$/, 'Login ID must be 4-32 alphanumeric/hyphen characters')
    .optional(),
  password: z
    .string()
    .min(8, 'Temporary password must be at least 8 characters')
    .max(128)
    .optional(),
});

export function calculateCompletionPercentage(
  candidate: Pick<
    Candidate,
    | 'personalInfo'
    | 'addressInfo'
    | 'familyInfo'
    | 'educationInfo'
    | 'employmentInfo'
    | 'bankDetails'
    | 'declaration'
  >,
  documents: CandidateDocument[]
): number {
  let score = 0;
  const weights = 8;

  if (personalInfoSchema.safeParse(candidate.personalInfo).success) score += 1;
  if (addressInfoSchema.safeParse(candidate.addressInfo).success) score += 1;
  if (familyInfoSchema.safeParse(candidate.familyInfo).success) score += 1;
  if (educationInfoSchema.safeParse(candidate.educationInfo).success) score += 1;
  if (employmentInfoSchema.safeParse(candidate.employmentInfo).success) score += 1;
  if (
    bankDetailsSchema
      .safeParse({
        ...candidate.bankDetails,
        confirmAccountNumber: candidate.bankDetails.accountNumber,
      })
      .success
  ) {
    score += 1;
  }

  const uploadedCategories = new Set(
    documents.filter((d) => d.verificationStatus !== 'Rejected').map((d) => d.category)
  );
  const reqCount = REQUIRED_DOCUMENT_CATEGORIES.filter((cat) =>
    uploadedCategories.has(cat)
  ).length;
  score += reqCount / REQUIRED_DOCUMENT_CATEGORIES.length;

  if (declarationSchema.safeParse(candidate.declaration).success) score += 1;

  return Math.min(100, Math.round((score / weights) * 100));
}
