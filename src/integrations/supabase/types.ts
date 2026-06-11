export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5"
  }
  public: {
    Tables: {
      email_scams: {
        Row: {
          category: string | null
          created_at: string
          detected_at: string
          id: string
          recipients_count: number
          sender: string
          severity: Database["public"]["Enums"]["threat_severity"]
          subject: string | null
          user_id: string | null
        }
        Insert: {
          category?: string | null
          created_at?: string
          detected_at?: string
          id?: string
          recipients_count?: number
          sender: string
          severity?: Database["public"]["Enums"]["threat_severity"]
          subject?: string | null
          user_id?: string | null
        }
        Update: {
          category?: string | null
          created_at?: string
          detected_at?: string
          id?: string
          recipients_count?: number
          sender?: string
          severity?: Database["public"]["Enums"]["threat_severity"]
          subject?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      malicious_ips: {
        Row: {
          country: string | null
          created_at: string
          id: string
          ip_address: string
          last_seen: string
          severity: Database["public"]["Enums"]["threat_severity"]
          threat_type: string | null
          user_id: string | null
        }
        Insert: {
          country?: string | null
          created_at?: string
          id?: string
          ip_address: string
          last_seen?: string
          severity?: Database["public"]["Enums"]["threat_severity"]
          threat_type?: string | null
          user_id?: string | null
        }
        Update: {
          country?: string | null
          created_at?: string
          id?: string
          ip_address?: string
          last_seen?: string
          severity?: Database["public"]["Enums"]["threat_severity"]
          threat_type?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      phishing_urls: {
        Row: {
          blocked_at: string
          created_at: string
          domain: string | null
          id: string
          notes: string | null
          severity: Database["public"]["Enums"]["threat_severity"]
          status: string
          url: string
          user_id: string | null
        }
        Insert: {
          blocked_at?: string
          created_at?: string
          domain?: string | null
          id?: string
          notes?: string | null
          severity?: Database["public"]["Enums"]["threat_severity"]
          status?: string
          url: string
          user_id?: string | null
        }
        Update: {
          blocked_at?: string
          created_at?: string
          domain?: string | null
          id?: string
          notes?: string | null
          severity?: Database["public"]["Enums"]["threat_severity"]
          status?: string
          url?: string
          user_id?: string | null
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          display_name: string | null
          id: string
        }
        Insert: {
          created_at?: string
          display_name?: string | null
          id: string
        }
        Update: {
          created_at?: string
          display_name?: string | null
          id?: string
        }
        Relationships: []
      }
      scam_detector_results: {
        Row: {
          classification: string
          confidence: number | null
          created_at: string
          id: string
          input_text: string
          raw_response: Json | null
          severity: Database["public"]["Enums"]["threat_severity"]
          user_id: string | null
        }
        Insert: {
          classification: string
          confidence?: number | null
          created_at?: string
          id?: string
          input_text: string
          raw_response?: Json | null
          severity?: Database["public"]["Enums"]["threat_severity"]
          user_id?: string | null
        }
        Update: {
          classification?: string
          confidence?: number | null
          created_at?: string
          id?: string
          input_text?: string
          raw_response?: Json | null
          severity?: Database["public"]["Enums"]["threat_severity"]
          user_id?: string | null
        }
        Relationships: []
      }
      scam_messages: {
        Row: {
          channel: string
          content: string
          created_at: string
          detected_at: string
          id: string
          sender: string | null
          severity: Database["public"]["Enums"]["threat_severity"]
          user_id: string | null
        }
        Insert: {
          channel?: string
          content: string
          created_at?: string
          detected_at?: string
          id?: string
          sender?: string | null
          severity?: Database["public"]["Enums"]["threat_severity"]
          user_id?: string | null
        }
        Update: {
          channel?: string
          content?: string
          created_at?: string
          detected_at?: string
          id?: string
          sender?: string | null
          severity?: Database["public"]["Enums"]["threat_severity"]
          user_id?: string | null
        }
        Relationships: []
      }
      spam_calls: {
        Row: {
          country: string | null
          created_at: string
          id: string
          pattern: string | null
          phone_number: string
          reported_at: string
          severity: Database["public"]["Enums"]["threat_severity"]
          user_id: string | null
        }
        Insert: {
          country?: string | null
          created_at?: string
          id?: string
          pattern?: string | null
          phone_number: string
          reported_at?: string
          severity?: Database["public"]["Enums"]["threat_severity"]
          user_id?: string | null
        }
        Update: {
          country?: string | null
          created_at?: string
          id?: string
          pattern?: string | null
          phone_number?: string
          reported_at?: string
          severity?: Database["public"]["Enums"]["threat_severity"]
          user_id?: string | null
        }
        Relationships: []
      }
      threats: {
        Row: {
          created_at: string
          description: string | null
          detected_at: string
          id: string
          severity: Database["public"]["Enums"]["threat_severity"]
          source: string | null
          status: string
          title: string
          type: Database["public"]["Enums"]["threat_type"]
          user_id: string | null
        }
        Insert: {
          created_at?: string
          description?: string | null
          detected_at?: string
          id?: string
          severity: Database["public"]["Enums"]["threat_severity"]
          source?: string | null
          status?: string
          title: string
          type: Database["public"]["Enums"]["threat_type"]
          user_id?: string | null
        }
        Update: {
          created_at?: string
          description?: string | null
          detected_at?: string
          id?: string
          severity?: Database["public"]["Enums"]["threat_severity"]
          source?: string | null
          status?: string
          title?: string
          type?: Database["public"]["Enums"]["threat_type"]
          user_id?: string | null
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "analyst" | "user"
      threat_severity: "critical" | "high" | "medium" | "low"
      threat_type:
        | "phishing_url"
        | "spam_call"
        | "email_scam"
        | "malicious_ip"
        | "scam_message"
        | "other"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "analyst", "user"],
      threat_severity: ["critical", "high", "medium", "low"],
      threat_type: [
        "phishing_url",
        "spam_call",
        "email_scam",
        "malicious_ip",
        "scam_message",
        "other",
      ],
    },
  },
} as const
