export interface WizardState {
  jobTypes:      string[];
  profile:       string;
  hostIDs:       string[];
  scheduleKey:   string;
  onceAt?:       string;
  cronExpr?:     string;
  scheduleName?: string;
  dailyTime?:    string;
  weeklyDay?:    number;
  weeklyTime?:   string;
  monthlyDay?:   number;
  maxCPUPct?:    number | null;
  maxMemoryMB?:  number | null;
  maxDurationS?: number | null;
}
