export type StaffRole = 'SUPER_ADMIN' | 'ADMIN' | 'HR';

export const ONBOARDING_STATUSES = [
  'Draft',
  'Link Sent',
  'In Progress',
  'Submitted',
  'Under Review',
  'Documents Pending',
  'Correction Required',
  'Approved',
  'Onboarding Completed',
  'Rejected',
] as const;

export type OnboardingStatus = (typeof ONBOARDING_STATUSES)[number];

export const DOCUMENT_CATEGORIES = [
  'Passport Size Photograph',
  'Aadhaar Card',
  'PAN Card',
  'Resume',
  'Educational Certificates',
  'Experience Letter',
  'Relieving Letter',
  'Bank Proof',
  'Other Documents',
] as const;

export type DocumentCategory = (typeof DOCUMENT_CATEGORIES)[number];

export const REQUIRED_DOCUMENT_CATEGORIES: DocumentCategory[] = [
  'Passport Size Photograph',
  'Aadhaar Card',
  'PAN Card',
  'Resume',
  'Educational Certificates',
  'Bank Proof',
];

export type DocumentVerificationStatus = 'Pending' | 'Approved' | 'Rejected';

export interface StaffUser {
  id: string;
  loginId: string;
  email: string;
  fullName: string;
  role: StaffRole;
  department: string;
  isActive: boolean;
  twoFactorEnabled: boolean;
  mustChangePassword?: boolean;
  isDemo: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}

export interface PersonalInformation {
  fullName: string;
  dateOfBirth: string;
  gender: 'Male' | 'Female' | 'Other' | 'Prefer not to say' | '';
  mobileNumber: string;
  email: string;
  maritalStatus: 'Single' | 'Married' | 'Divorced' | 'Widowed' | '';
}

export interface AddressInformation {
  currentAddress: string;
  permanentAddress: string;
  sameAsCurrent: boolean;
  city: string;
  state: string;
  pinCode: string;
}

export interface FamilyInformation {
  fatherName: string;
  motherName: string;
  spouseName?: string;
  emergencyContactName: string;
  emergencyContactRelation: string;
  emergencyContactPhone: string;
}

export interface EducationalInformation {
  highestQualification: string;
  collegeUniversity: string;
  passingYear: string;
  percentageOrCgpa: string;
}

export interface EmploymentInformation {
  isFresher: boolean;
  previousCompany?: string;
  previousDesignation?: string;
  previousExperience?: string;
  lastWorkingDate?: string;
  previousSalary?: string;
}

export interface BankDetails {
  accountHolderName: string;
  bankName: string;
  accountNumber: string;
  confirmAccountNumber?: string;
  ifscCode: string;
}

export interface DeclarationInformation {
  accepted: boolean;
  digitalSignature: string;
  submittedAt?: string;
}

export interface DocumentVerificationHistoryItem {
  id: string;
  status: DocumentVerificationStatus;
  reviewedById: string;
  reviewedByName: string;
  reason?: string;
  timestamp: string;
}

export interface CandidateDocument {
  id: string;
  candidateId: string;
  category: DocumentCategory;
  originalName: string;
  mimeType: string;
  sizeBytes: number;
  storageKey: string;
  verificationStatus: DocumentVerificationStatus;
  rejectionReason?: string;
  uploadedAt: string;
  verifiedAt?: string;
  verifiedByName?: string;
  history: DocumentVerificationHistoryItem[];
}

export interface OnboardingToken {
  id: string;
  candidateId: string;
  token: string;
  expiresAt: string;
  isRevoked: boolean;
  createdAt: string;
  createdByName: string;
  lastAccessedAt?: string;
}

export interface StatusHistoryEntry {
  id: string;
  candidateId: string;
  fromStatus: OnboardingStatus | null;
  toStatus: OnboardingStatus;
  changedById: string;
  changedByName: string;
  changedByRole: string;
  note?: string;
  timestamp: string;
}

export interface Candidate {
  id: string;
  candidateCode: string;
  fullName: string;
  email: string;
  mobile: string;
  position: string;
  department: string;
  joiningDate: string;
  assignedRecruiterId: string;
  assignedRecruiterName: string;
  status: OnboardingStatus;
  completionPct: number;
  correctionNotes?: string;
  employeeId?: string;
  employeeCode?: string;
  isDemo: boolean;
  createdAt: string;
  updatedAt: string;
  personalInfo: PersonalInformation;
  addressInfo: AddressInformation;
  familyInfo: FamilyInformation;
  educationInfo: EducationalInformation;
  employmentInfo: EmploymentInformation;
  bankDetails: BankDetails;
  declaration: DeclarationInformation;
}

export interface Employee {
  id: string;
  employeeCode: string;
  candidateId: string;
  candidateCode: string;
  fullName: string;
  email: string;
  mobile: string;
  position: string;
  department: string;
  joiningDate: string;
  assignedRecruiterName: string;
  personalInfo: PersonalInformation;
  addressInfo: AddressInformation;
  familyInfo: FamilyInformation;
  educationInfo: EducationalInformation;
  employmentInfo: EmploymentInformation;
  bankDetails: Omit<BankDetails, 'confirmAccountNumber'>;
  isDemo: boolean;
  createdById: string;
  createdByName: string;
  createdAt: string;
  updatedAt: string;
}

export interface NotificationRecord {
  id: string;
  type:
    | 'ONBOARDING_INVITATION'
    | 'CANDIDATE_SUBMITTED'
    | 'DOCUMENTS_PENDING'
    | 'DOCUMENT_REJECTED'
    | 'CORRECTION_REQUESTED'
    | 'FINAL_APPROVAL'
    | 'ONBOARDING_COMPLETED';
  title: string;
  message: string;
  recipientEmail: string;
  recipientName: string;
  candidateId?: string;
  candidateCode?: string;
  onboardingUrl?: string;
  deliveryStatus: 'SENT_SMTP' | 'PENDING_MANUAL_SHARE' | 'IN_APP_ONLY';
  deliveryNote: string;
  isRead: boolean;
  createdAt: string;
}

export interface AuditLog {
  id: string;
  actorId: string;
  actorName: string;
  actorRole: string;
  action: string;
  targetType: 'AUTH' | 'STAFF' | 'CANDIDATE' | 'TOKEN' | 'DOCUMENT' | 'EMPLOYEE' | 'SYSTEM';
  targetId: string;
  details: string;
  ipAddress: string;
  timestamp: string;
}

export interface SystemConfig {
  defaultLinkExpiryHours: number;
  maxUploadSizeMb: number;
  departments: string[];
  smtpConfigured: boolean;
  demoModeEnabled: boolean;
  updatedAt: string;
}

export interface AnalyticsSummary {
  kpis: {
    totalCandidates: number;
    newApplications: number;
    pendingOnboarding: number;
    documentsPending: number;
    documentsVerified: number;
    onboardingCompleted: number;
    rejectedApplications: number;
  };
  monthlyStats: Array<{ month: string; registered: number; completed: number }>;
  departmentStats: Array<{ department: string; count: number; completed: number }>;
  statusDistribution: Array<{ status: string; count: number }>;
  conversionFunnel: Array<{ stage: string; count: number; rate: number }>;
}
