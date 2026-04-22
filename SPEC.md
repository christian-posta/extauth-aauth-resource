
draft-hardt-aauth-protocol-01 - AAuth Protocol
    

        
        
        
        
        
        
        
        
        

    
    
        
            
                
                    
                        
                            
                            Datatracker
                            
                        
                        
                            
                                
    
        
            Groups
        
        
        
    By area/parent
    
    
        
            Apps &amp; Realtime
        
    
    
        
            General
        
    
    
        
            Internet
        
    
    
        
            Ops &amp; Management
        
    
    
        
            Routing
        
    
    
        
            Security
        
    
    
        
            Web and Internet Transport
        
    
    
        IESG
    
    
        
            IAB
        
    
    
        
            IRTF
        
    
    
        
            IETF LLC
        
    
    
        
            RFC Editor
        
    
    
        
            Other
        
        
    

    
        
            Active AGs
        
    
        
            Active Areas
        
    
        
            Active Directorates
        
    
        
            Active IAB Workshops
        
    
        
            Active Programs
        
    
        
            Active RAGs
        
    
        
            Active Teams
        
    
    

    
    
    New work
    
        
            Chartering groups
        
    
    
        
            BOFs
        
    
    
        
            BOF Requests
        
    
    
    Other groups
    
        
            Concluded groups
        
    
    
        
            Non-WG lists
        
    
    
    
    

    
        
            Documents
        
        
        
    
        
            Search
        
    
    
        
            Recent I-Ds
        
    
    
        
            Submit an Internet-Draft
        
    
    
    
        
        
    
    
        RFC streams
    
    
        
            IAB
        
    
    
        
            IRTF
        
    
    
        
            ISE
        
    
    
        
            Editorial
        
    
    
        
        
    
    
        Subseries
    
    
        
            STD
        
        
            BCP
        
        
            FYI
        
    
    
    
    

    
        
            Meetings
        
        
        
    
        
            Agenda
        
    
    
        
            Materials
        
    
    
        
            Floor plan
        
    
    
        
            Registration
        
    
    
        
            Important dates
        
    
    
        
            Request a session
        
    
    
        
            Session requests
        
    
    
    
        
            
            
        
        
            Upcoming meetings
        
    
    
        
            Upcoming meetings
        
    
    
        
            
            
        
        
            Past meetings
        
    
    
        
            Past meetings
        
    
    
        
            Meeting proceedings
        
    
    
    
    

    
        
            Other
        
        
        
    
        
            IPR disclosures
        
    
    
    
        
            IESG agenda
        
    
    
        
            NomComs
        
    
    
        
            Downref registry
        
    
    
        
            Statistics
        
        
            
                
                    I-Ds/RFCs
                
            
            
                
                    Meetings
                
            
            
                
            
        
    
    
        
            API Help
        
    
    
        
            Release notes
        
    
    
        
            System status
        
    
    
        
        
    
    
    
        
            
            
            Report a bug
        
    
    
    
    

    
        
            
                
                    User
                
            
            
            
    
    
        
            
                
                    Sign in
                
            
            
                
                    Password reset
                
            
            
                
                    Preferences
                
            
        
    
    
        
            
                New account
            
        
    
    
      
        List subscriptions
      
      
            
                
                    IETF Lists
                
            
            
                
                IRTF Lists
                
            
            
                
                    IAB Lists
                
            
            
                
                    RFC-Editor Lists
                
            
        
    
    
    
    
    
    
    
    
    
        
            
            
            Report a bug
            
        
    
    
        
            
                
                
                    
    AAuth Protocol
    
    draft-hardt-aauth-protocol-01


    
        
            
                Status
            
        
    
        
            
                Email expansions
            
        
    
        
            
                History
            
        
    

    
        
    Versions:
    
    
        
            
                 
                    
                        
                            00
                        
                    
                
            
                 
                    
                        
                            01
                        
                    
                
            
            
        
    
    
        
    
    
    
    
        
    
        This document is an Internet-Draft (I-D).
        Anyone may submit an I-D to the IETF.
        This I-D is not endorsed by the IETF and has no formal standing in the
        IETF standards process.
    
    
    
        
    
    
    
    
        
    
    
    Document
    Type
    
    
        
    
    
    
    
    
    
    
    
    Active Internet-Draft
    (individual)
    
    
            
            
            
        
    
    
    
        
        Author
        
            
        
        
            
            
                Dick Hardt 
                
            
            
        
    
    
    
    
        
        Last updated
        
        
            2026-04-13
            
        
    
    
    
        
        
        
    
    
        
        
            RFC stream
        
        
            
        
        
            
                (None)
            
        
    
    
        
            
            
                Intended RFC status
            
            
                
            
            
                
                    
                        (None)
                    
                
            
        
    
    
        
        
            Formats
        
        
        
        
            
                
    
    
        
        
            
                 txt
            
        
        
    
        
        
            
                 html
            
        
        
    
        
        
            
                 xml
            
        
        
    
        
        
            
                 htmlized
            
        
        
    
        
        
            
                 bibtex
            
        
        
    
        
        
            
                 bibxml
            
        
        
    
    
            
        
    
    
    
    
        
    
        
            
            
        
    
    
        
    
    
        
            
                
                    draft-hardt-aauth-protocol-01
                
            
            
                TBD                                                             D. Hardt
Internet-Draft                                                     Hellō
Intended status: Standards Track                           13 April 2026
Expires: 15 October 2026
                             AAuth Protocol
                     draft-hardt-aauth-protocol-01
Abstract
   This document defines the AAuth authorization protocol for agent-to-
   resource authorization and identity claim retrieval.  The protocol
   supports four resource access modes — identity-based, resource-
   managed (two-party), PS-managed (three-party), and federated (four-
   party) — with agent governance as an orthogonal layer.  It builds on
   the HTTP Signature Keys specification
   ([I-D.hardt-httpbis-signature-key]) for HTTP Message Signatures and
   key discovery.
Discussion Venues
   _Note: This section is to be removed before publishing as an RFC._
   This document is part of the AAuth specification family.  Source for
   this draft and an issue tracker can be found at
   https://github.com/dickhardt/AAuth (https://github.com/dickhardt/
   AAuth).
Status of This Memo
   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.
   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF).  Note that other groups may also distribute
   working documents as Internet-Drafts.  The list of current Internet-
   Drafts is at https://datatracker.ietf.org/drafts/current/.
   Internet-Drafts are draft documents valid for a maximum of six months
   and may be updated, replaced, or obsoleted by other documents at any
   time.  It is inappropriate to use Internet-Drafts as reference
   material or to cite them other than as &quot;work in progress.&quot;
   This Internet-Draft will expire on 15 October 2026.
Hardt                    Expires 15 October 2026                [Page 1]
Internet-Draft               AAuth-Protocol                   April 2026
Copyright Notice
   Copyright (c) 2026 IETF Trust and the persons identified as the
   document authors.  All rights reserved.
   This document is subject to BCP 78 and the IETF Trust&#x27;s Legal
   Provisions Relating to IETF Documents (https://trustee.ietf.org/
   license-info) in effect on the date of publication of this document.
   Please review these documents carefully, as they describe your rights
   and restrictions with respect to this document.  Code Components
   extracted from this document must include Revised BSD License text as
   described in Section 4.e of the Trust Legal Provisions and are
   provided without warranty as described in the Revised BSD License.
Table of Contents
   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . . . .   6
     1.1.  HTTP Clients Need Their Own Identity  . . . . . . . . . .   7
     1.2.  Agents Are Different  . . . . . . . . . . . . . . . . . .   7
     1.3.  What AAuth Provides . . . . . . . . . . . . . . . . . . .   7
     1.4.  What AAuth Does Not Do  . . . . . . . . . . . . . . . . .   8
     1.5.  Relationship to Existing Standards  . . . . . . . . . . .   8
   2.  Conventions and Definitions . . . . . . . . . . . . . . . . .   9
   3.  Terminology . . . . . . . . . . . . . . . . . . . . . . . . .   9
   4.  Protocol Overview . . . . . . . . . . . . . . . . . . . . . .  11
     4.1.  Resource Access Modes . . . . . . . . . . . . . . . . . .  11
       4.1.1.  Identity-Based Access . . . . . . . . . . . . . . . .  13
       4.1.2.  Resource-Managed Access (Two-Party) . . . . . . . . .  13
       4.1.3.  PS-Managed Access (Three-Party) . . . . . . . . . . .  14
       4.1.4.  Federated Access (Four-Party) . . . . . . . . . . . .  15
       4.1.5.  Agent Server as Resource  . . . . . . . . . . . . . .  16
     4.2.  Agent Governance  . . . . . . . . . . . . . . . . . . . .  17
       4.2.1.  Missions  . . . . . . . . . . . . . . . . . . . . . .  17
       4.2.2.  PS Governance Endpoints . . . . . . . . . . . . . . .  18
     4.3.  Obtaining an Agent Token  . . . . . . . . . . . . . . . .  19
     4.4.  Bootstrapping . . . . . . . . . . . . . . . . . . . . . .  19
   5.  Agent Identity  . . . . . . . . . . . . . . . . . . . . . . .  20
     5.1.  Agent Identifiers . . . . . . . . . . . . . . . . . . . .  20
     5.2.  Agent Token . . . . . . . . . . . . . . . . . . . . . . .  21
       5.2.1.  Agent Token Acquisition . . . . . . . . . . . . . . .  21
       5.2.2.  Agent Token Structure . . . . . . . . . . . . . . . .  21
       5.2.3.  Agent Token Usage . . . . . . . . . . . . . . . . . .  22
       5.2.4.  Agent Token Verification  . . . . . . . . . . . . . .  22
   6.  Resource Access and Resource Tokens . . . . . . . . . . . . .  22
     6.1.  Authorization Endpoint Request  . . . . . . . . . . . . .  23
     6.2.  Authorization Endpoint Responses  . . . . . . . . . . . .  24
       6.2.1.  Response without Resource Token . . . . . . . . . . .  24
       6.2.2.  Response with Resource Token  . . . . . . . . . . . .  25
       6.2.3.  Authorization Endpoint Error Responses  . . . . . . .  25
     6.3.  AAuth-Access Response Header  . . . . . . . . . . . . . .  26
     6.4.  Resource-Managed Authorization  . . . . . . . . . . . . .  26
     6.5.  Auth Token Required . . . . . . . . . . . . . . . . . . .  27
     6.6.  Resource Token  . . . . . . . . . . . . . . . . . . . . .  27
       6.6.1.  Resource Token Structure  . . . . . . . . . . . . . .  28
       6.6.2.  Resource Token Verification . . . . . . . . . . . . .  28
       6.6.3.  Resource Challenge Verification . . . . . . . . . . .  29
   7.  Person Server . . . . . . . . . . . . . . . . . . . . . . . .  29
     7.1.  PS Token Endpoint . . . . . . . . . . . . . . . . . . . .  29
       7.1.1.  Token Endpoint Modes  . . . . . . . . . . . . . . . .  29
       7.1.2.  Concurrent Token Requests . . . . . . . . . . . . . .  30
       7.1.3.  Agent Token Request . . . . . . . . . . . . . . . . .  30
       7.1.4.  PS Response . . . . . . . . . . . . . . . . . . . . .  31
     7.2.  User Interaction  . . . . . . . . . . . . . . . . . . . .  32
     7.3.  Clarification Chat  . . . . . . . . . . . . . . . . . . .  32
       7.3.1.  Clarification Required  . . . . . . . . . . . . . . .  32
       7.3.2.  Clarification Flow  . . . . . . . . . . . . . . . . .  33
       7.3.3.  Agent Response to Clarification . . . . . . . . . . .  33
       7.3.4.  Clarification Limits  . . . . . . . . . . . . . . . .  35
     7.4.  Permission Endpoint . . . . . . . . . . . . . . . . . . .  35
       7.4.1.  Permission Request  . . . . . . . . . . . . . . . . .  35
       7.4.2.  Permission Response . . . . . . . . . . . . . . . . .  36
     7.5.  Audit Endpoint  . . . . . . . . . . . . . . . . . . . . .  37
       7.5.1.  Audit Request . . . . . . . . . . . . . . . . . . . .  37
       7.5.2.  Audit Response  . . . . . . . . . . . . . . . . . . .  38
     7.6.  Interaction Endpoint  . . . . . . . . . . . . . . . . . .  38
       7.6.1.  Interaction Request . . . . . . . . . . . . . . . . .  39
       7.6.2.  Interaction Response  . . . . . . . . . . . . . . . .  40
     7.7.  Re-authorization  . . . . . . . . . . . . . . . . . . . .  41
   8.  Mission . . . . . . . . . . . . . . . . . . . . . . . . . . .  41
     8.1.  Mission Creation  . . . . . . . . . . . . . . . . . . . .  41
     8.2.  Mission Approval  . . . . . . . . . . . . . . . . . . . .  42
     8.3.  Mission Log . . . . . . . . . . . . . . . . . . . . . . .  44
     8.4.  Mission Completion  . . . . . . . . . . . . . . . . . . .  44
     8.5.  Mission Management  . . . . . . . . . . . . . . . . . . . .  44
     8.6.  Mission Status Errors . . . . . . . . . . . . . . . . . .  45
     8.7.  AAuth-Mission Request Header  . . . . . . . . . . . . . .  45
   9.  Access Server Federation  . . . . . . . . . . . . . . . . . .  46
     9.1.  AS Token Endpoint . . . . . . . . . . . . . . . . . . . .  46
       9.1.1.  PS-to-AS Token Request  . . . . . . . . . . . . . . .  46
       9.1.2.  AS Response . . . . . . . . . . . . . . . . . . . . .  47
       9.1.3.  Auth Token Delivery . . . . . . . . . . . . . . . . .  48
     9.2.  Claims Required . . . . . . . . . . . . . . . . . . . . .  49
     9.3.  PS-AS Federation  . . . . . . . . . . . . . . . . . . . .  49
       9.3.1.  PS-AS Trust Establishment . . . . . . . . . . . . . .  49
       9.3.2.  AS Decision Logic (Non-Normative) . . . . . . . . . .  51
       9.3.3.  Organization Visibility . . . . . . . . . . . . . . .  52
     9.4.  Auth Token  . . . . . . . . . . . . . . . . . . . . . . .  52
       9.4.1.  Auth Token Structure  . . . . . . . . . . . . . . . .  52
       9.4.2.  Auth Token Usage  . . . . . . . . . . . . . . . . . .  53
       9.4.3.  Auth Token Verification . . . . . . . . . . . . . . .  53
       9.4.4.  Auth Token Response Verification  . . . . . . . . . .  54
       9.4.5.  Upstream Token Verification . . . . . . . . . . . . .  54
   10. Multi-Hop Resource Access . . . . . . . . . . . . . . . . . .  55
     10.1.  Call Chaining  . . . . . . . . . . . . . . . . . . . . .  55
     10.2.  Interaction Chaining . . . . . . . . . . . . . . . . . .  56
   11. Third-Party Login . . . . . . . . . . . . . . . . . . . . . .  56
     11.1.  Login Endpoint . . . . . . . . . . . . . . . . . . . . .  57
     11.2.  Login Flow . . . . . . . . . . . . . . . . . . . . . . .  57
     11.3.  Security Considerations for Third-Party Login  . . . . .  58
   12. Protocol Primitives . . . . . . . . . . . . . . . . . . . . .  59
     12.1.  AAuth-Capabilities Request Header  . . . . . . . . . . .  59
     12.2.  Scopes . . . . . . . . . . . . . . . . . . . . . . . . .  60
     12.3.  Requirement Responses  . . . . . . . . . . . . . . . . .  61
       12.3.1.  AAuth-Requirement Header Structure . . . . . . . . .  61
       12.3.2.  Requirement Values . . . . . . . . . . . . . . . . .  62
       12.3.3.  Interaction Required . . . . . . . . . . . . . . . .  62
       12.3.4.  Approval Pending . . . . . . . . . . . . . . . . . .  64
     12.4.  Deferred Responses . . . . . . . . . . . . . . . . . . .  65
       12.4.1.  Initial Request  . . . . . . . . . . . . . . . . . .  65
       12.4.2.  Pending Response . . . . . . . . . . . . . . . . . .  65
       12.4.3.  Polling with GET . . . . . . . . . . . . . . . . . .  66
       12.4.4.  Deferred Response State Machine  . . . . . . . . . .  66
     12.5.  Error Responses  . . . . . . . . . . . . . . . . . . . .  67
       12.5.1.  Authentication Errors  . . . . . . . . . . . . . . .  67
       12.5.2.  Token Endpoint Error Response Format . . . . . . . .  67
       12.5.3.  Token Endpoint Error Codes . . . . . . . . . . . . .  67
       12.5.4.  Polling Error Codes  . . . . . . . . . . . . . . . .  68
     12.6.  Token Revocation . . . . . . . . . . . . . . . . . . . .  69
     12.7.  HTTP Message Signatures Profile  . . . . . . . . . . . .  70
       12.7.1.  Signature Algorithms . . . . . . . . . . . . . . . .  70
       12.7.2.  Keying Material  . . . . . . . . . . . . . . . . . .  70
       12.7.3.  Signing (Agent)  . . . . . . . . . . . . . . . . . .  71
       12.7.4.  Verification (Server)  . . . . . . . . . . . . . . .  71
     12.8.  JWKS Discovery and Caching . . . . . . . . . . . . . . .  72
     12.9.  Identifiers  . . . . . . . . . . . . . . . . . . . . . .  72
       12.9.1.  Server Identifiers . . . . . . . . . . . . . . . . .  72
       12.9.2.  Endpoint URLs  . . . . . . . . . . . . . . . . . . .  73
       12.9.3.  Other URLs . . . . . . . . . . . . . . . . . . . . .  73
     12.10. Metadata Documents . . . . . . . . . . . . . . . . . . .  73
       12.10.1.  Agent Server Metadata . . . . . . . . . . . . . . .  74
       12.10.2.  Person Server Metadata  . . . . . . . . . . . . . .  74
       12.10.3.  Access Server Metadata  . . . . . . . . . . . . . .  75
       12.10.4.  Resource Metadata . . . . . . . . . . . . . . . . .  76
   13. Incremental Adoption  . . . . . . . . . . . . . . . . . . . .  77
     13.1.  Agent Adoption Path  . . . . . . . . . . . . . . . . . .  77
     13.2.  Resource Adoption Path . . . . . . . . . . . . . . . . .  77
     13.3.  Adoption Matrix  . . . . . . . . . . . . . . . . . . . .  78
   14. Security Considerations . . . . . . . . . . . . . . . . . . .  79
     14.1.  Proof-of-Possession  . . . . . . . . . . . . . . . . . .  79
     14.2.  Token Security . . . . . . . . . . . . . . . . . . . . .  79
     14.3.  Pending URL Security . . . . . . . . . . . . . . . . . .  79
     14.4.  Clarification Chat Security  . . . . . . . . . . . . . .  79
     14.5.  Untrusted Input  . . . . . . . . . . . . . . . . . . . .  79
     14.6.  Interaction Code Misdirection  . . . . . . . . . . . . .  80
     14.7.  AS Discovery . . . . . . . . . . . . . . . . . . . . . .  80
     14.8.  AAuth-Access Security  . . . . . . . . . . . . . . . . .  80
     14.9.  PS as Auth Token Issuer  . . . . . . . . . . . . . . . .  80
     14.10. Agent-Person Binding . . . . . . . . . . . . . . . . . .  80
     14.11. PS as High-Value Target  . . . . . . . . . . . . . . . .  81
     14.12. Call Chaining Identity . . . . . . . . . . . . . . . . .  81
     14.13. Token Revocation and Lifecycle . . . . . . . . . . . . .  81
     14.14. TLS Requirements . . . . . . . . . . . . . . . . . . . .  82
   15. Privacy Considerations  . . . . . . . . . . . . . . . . . . .  82
     15.1.  Directed Identifiers . . . . . . . . . . . . . . . . . .  82
     15.2.  PS Visibility  . . . . . . . . . . . . . . . . . . . . .  82
     15.3.  Mission Content Exposure . . . . . . . . . . . . . . . .  82
   16. IANA Considerations . . . . . . . . . . . . . . . . . . . . .  82
     16.1.  HTTP Header Field Registration . . . . . . . . . . . . .  82
     16.2.  HTTP Authentication Scheme Registration  . . . . . . . .  83
     16.3.  Well-Known URI Registrations . . . . . . . . . . . . . .  83
     16.4.  Media Type Registrations . . . . . . . . . . . . . . . .  84
       16.4.1.  application/aa-agent+jwt . . . . . . . . . . . . . .  84
       16.4.2.  application/aa-auth+jwt  . . . . . . . . . . . . . .  84
       16.4.3.  application/aa-resource+jwt  . . . . . . . . . . . .  85
     16.5.  JWT Type Registrations . . . . . . . . . . . . . . . . .  85
     16.6.  JWT Claims Registrations . . . . . . . . . . . . . . . .  85
     16.7.  AAuth Requirement Value Registry . . . . . . . . . . . .  86
     16.8.  AAuth Capability Value Registry  . . . . . . . . . . . .  86
     16.9.  URI Scheme Registration  . . . . . . . . . . . . . . . .  87
   17. Implementation Status . . . . . . . . . . . . . . . . . . . .  87
   18. Document History  . . . . . . . . . . . . . . . . . . . . . .  88
   19. Acknowledgments . . . . . . . . . . . . . . . . . . . . . . .  88
   20. References  . . . . . . . . . . . . . . . . . . . . . . . . .  88
     20.1.  Normative References . . . . . . . . . . . . . . . . . .  88
     20.2.  Informative References . . . . . . . . . . . . . . . . .  91
   Appendix A.  Agent Token Acquisition Patterns . . . . . . . . . .  92
     A.1.  Self-Hosted Agents  . . . . . . . . . . . . . . . . . . .  92
     A.2.  User Login  . . . . . . . . . . . . . . . . . . . . . . .  93
     A.3.  Desktop and CLI Applications  . . . . . . . . . . . . . .  93
     A.4.  Mobile Applications . . . . . . . . . . . . . . . . . . .  94
     A.5.  Browser-Based Applications  . . . . . . . . . . . . . . .  94
     A.6.  Server Workloads  . . . . . . . . . . . . . . . . . . . .  94
     A.7.  Managed Desktops  . . . . . . . . . . . . . . . . . . . .  95
   Appendix B.  Detailed Flows . . . . . . . . . . . . . . . . . . .  95
     B.1.  Two-Party: Resource-Managed with Interaction  . . . . . .  95
     B.2.  Four-Party: 401 Resource Challenge  . . . . . . . . . . .  96
     B.3.  Four-Party: User Authorization  . . . . . . . . . . . . .  97
     B.4.  Four-Party: Direct Approval . . . . . . . . . . . . . . .  98
     B.5.  Four-Party: Call Chaining . . . . . . . . . . . . . . . .  99
     B.6.  Interaction Chaining  . . . . . . . . . . . . . . . . . . 100
   Appendix C.  Design Rationale . . . . . . . . . . . . . . . . . . 102
     C.1.  Identity and Foundation . . . . . . . . . . . . . . . . . 102
       C.1.1.  Why HTTPS-Based Agent Identity  . . . . . . . . . . . 102
       C.1.2.  Why Per-Instance Agent Identity . . . . . . . . . . . 102
       C.1.3.  Why Every Agent Has a Person  . . . . . . . . . . . . 102
       C.1.4.  Why the ps Claim in Agent Tokens  . . . . . . . . . . 103
     C.2.  Protocol Mechanics  . . . . . . . . . . . . . . . . . . . 103
       C.2.1.  Why .json in Well-Known URIs  . . . . . . . . . . . . 103
       C.2.2.  Why Standard HTTP Async Pattern . . . . . . . . . . . 103
       C.2.3.  Why JSON Instead of Form-Encoded  . . . . . . . . . . 103
       C.2.4.  Why No Authorization Code . . . . . . . . . . . . . . 103
       C.2.5.  Why Callback URL Has No Security Role . . . . . . . . 104
       C.2.6.  Why No Refresh Token  . . . . . . . . . . . . . . . . 104
       C.2.7.  Why Reuse OpenID Connect Vocabulary . . . . . . . . . 104
     C.3.  Architecture  . . . . . . . . . . . . . . . . . . . . . . 104
       C.3.1.  Why a Separate Person Server  . . . . . . . . . . . . 104
       C.3.2.  Why Four Adoption Modes . . . . . . . . . . . . . . . 104
       C.3.3.  Why Resource Tokens . . . . . . . . . . . . . . . . . 105
       C.3.4.  Why Opaque AAuth-Access Tokens  . . . . . . . . . . . 105
       C.3.5.  Why Missions Are Not a Policy Language  . . . . . . . 105
       C.3.6.  Why Missions Have Only Two States . . . . . . . . . . 107
       C.3.7.  Why Downstream Scope Is Not Constrained by Upstream
               Scope . . . . . . . . . . . . . . . . . . . . . . . . 107
     C.4.  Comparisons with Alternatives . . . . . . . . . . . . . . 107
       C.4.1.  Why Not mTLS? . . . . . . . . . . . . . . . . . . . . 107
       C.4.2.  Why Not DPoP? . . . . . . . . . . . . . . . . . . . . 108
       C.4.3.  Why Not Extend GNAP . . . . . . . . . . . . . . . . . 108
       C.4.4.  Why Not Extend WWW-Authenticate?  . . . . . . . . . . 109
       C.4.5.  Why Not Extend OAuth? . . . . . . . . . . . . . . . . 110
   Author&#x27;s Address  . . . . . . . . . . . . . . . . . . . . . . . . 111
   1.  Introduction
   1.1.  HTTP Clients Need Their Own Identity
   In OAuth 2.0 [RFC6749] and OpenID Connect [OpenID.Core], the client
   has no independent identity.  Client identifiers are issued by each
   authorization server or OpenID provider — a client_id at Google is
   meaningless at GitHub.  The client&#x27;s identity exists only in the
   context of each server it has pre-registered with.  This made sense
   when the web had a manageable number of integrations and a human
   developer could visit each portal to register.
   API keys are the same model pushed further: a shared secret issued by
   a service, copied to the client, and used as a bearer credential.
   The problem is that any secret that must be copied to where the
   workload runs will eventually be copied somewhere it shouldn&#x27;t be.
   SPIFFE and WIMSE brought workload identity to enterprise
   infrastructure — a workload can prove who it is without shared
   secrets.  But these operate within a single enterprise&#x27;s trust
   domain.  They don&#x27;t help an agent that needs to access resources
   across organizational boundaries, or a developer&#x27;s tool that runs
   outside any enterprise platform.
   AAuth starts from this premise: every agent has its own cryptographic
   identity.  An agent identifier (aauth:local@domain) is bound to a
   signing key, published at a well-known URL, and verifiable by any
   party — no pre-registration, no shared secrets, no dependency on a
   particular server.  At its simplest, an agent signs a request and a
   resource decides what to do based on who the agent is.  This
   identity-based access replaces API keys and is the foundation that
   authorization, governance, and federation build on incrementally.
   1.2.  Agents Are Different
   Traditional software knows at build time what services it will call
   and what permissions it needs.  Registration, key provisioning, and
   scope configuration happen before the first request.  This works when
   the set of integrations is fixed and known in advance.
   Agents don&#x27;t work this way.  They discover resources at runtime.
   They execute long-running tasks that span multiple services across
   trust domains.  They need to explain what they&#x27;re doing and why.
   They need authorization decisions mid-task, long after the user set
   them in motion.  A protocol designed for pre-registered clients with
   fixed integrations cannot serve agents that discover their needs as
   they go.
   1.3.  What AAuth Provides
   *  *Agent identity without pre-registration*: A domain, static
      metadata, and a JWKS establish identity with no portal, no
      bilateral agreement, no shared secret.
   *  *Per-instance identity*: Each agent instance gets its own
      identifier (aauth:local@domain) and signing key.
   *  *Proof-of-possession on every request*: HTTP Message Signatures
      ([RFC9421]) bind every request to the agent&#x27;s key — a stolen token
      is useless without the private key.
   *  *Two-party mode with first-call registration*: An agent calls a
      resource it has never contacted before; the resource returns
      AAuth-Requirement; a browser interaction handles account creation,
      payment, and consent.  The first API call is the registration.
   *  *Tool-call governance*: A person server (PS) represents the user
      and manages what tools the agent can call, providing permission
      and audit for tool use — no resource involved.
   *  *Missions*: Optional scoped authorization contexts that span
      multiple resources.  The agent proposes what it intends to do in
      natural language; the person server provides full context —
      mission, history, justification — to the appropriate decision-
      maker (human or AI); every resource access is evaluated in
      context.  Missions enable governance over decisions that cannot be
      reduced to predefined machine-evaluable rules.
   *  *Cross-domain federation*: The PS federates with access servers
      (AS) — the policy engines that guard resources — to enable access
      across trust domains without the agent needing to know about each
      one.
   *  *Clarification chat*: Users can ask questions during consent;
      agents can explain or adjust their requests.
   *  *Progressive adoption*: Each party can adopt independently; modes
      build on each other.
   1.4.  What AAuth Does Not Do
   *  Does not require centralized identity providers — agents publish
      their own identity
   *  Does not use shared secrets or bearer tokens — every credential is
      bound to a signing key and useless without it
   *  Does not require coordination to adopt — each party adds support
      independently
   1.5.  Relationship to Existing Standards
   AAuth builds on existing standards and design patterns:
   *  *OpenID Connect vocabulary*: AAuth reuses OpenID Connect scope
      values, identity claims, and enterprise extensions
      ([OpenID.Enterprise]), lowering the adoption barrier for identity-
      aware resources.
   *  *Well-known metadata and key discovery*: Servers publish metadata
      at well-known URLs ([RFC8615]) and signing keys via JWKS
      endpoints, following the pattern established by OAuth
      Authorization Server Metadata ([RFC8414]) and OpenID Connect
      Discovery ([OpenID.Core]).
   *  *HTTP Message Signatures*: All requests are signed with HTTP
      Message Signatures ([RFC9421]) using keys bound to tokens conveyed
      via the Signature-Key header ([I-D.hardt-httpbis-signature-key]),
      providing proof-of-possession, identity, and message integrity on
      every call.
   The HTTP Signature Keys specification
   ([I-D.hardt-httpbis-signature-key]) defines how signing keys are
   bound to JWTs and discovered via well-known metadata, and how agents
   present cryptographic identity using HTTP Message Signatures
   ([RFC9421]).  This specification defines the AAuth-Requirement,
   AAuth-Access, and AAuth-Capabilities headers, and the authorization
   protocol across four resource access modes.
   Because agent identity is independent and self-contained, AAuth is
   designed for incremental adoption — each party can add support
   independently, and rollout does not need to be coordinated.  A
   resource that verifies an agent&#x27;s signature can manage access by
   identity alone, with no other infrastructure.  When a resource
   manages its own authorization — via interaction, consent, or existing
   infrastructure — it operates in resource-managed access (two-party).
   Issuing resource tokens to the agent&#x27;s person server enables PS-
   managed access (three-party), where auth tokens carry user identity,
   organization membership, and group information.  Deploying an access
   server enables federated access (four-party) with cross-domain policy
   enforcement.  Agent governance — missions, permissions, audit — is an
   orthogonal layer that any agent with a PS can add, from a simple
   prompt to full autonomous agent oversight.  See Section 13 for
   details.
   2.  Conventions and Definitions
   {::boilerplate bcp14-tagged}
   In HTTP examples throughout this document, line breaks and
   indentation are added for readability.  Actual HTTP messages do not
   contain these extra line breaks.
   3.  Terminology
   Parties:
   *  *Person*: A user or organization — the legal person — on whose
      behalf an agent acts and who is accountable for the agent&#x27;s
      actions.
   *  *Agent*: An HTTP client ([RFC9110], Section 3.5) acting on behalf
      of a person.  Identified by an agent identifier URIs using the
      aauth scheme, of the form aauth:local@domain Section 5.1.  An
      agent MAY have a person server, declared via the ps claim in the
      agent token.
   *  *Agent Server*: A server that manages agent identity and issues
      agent tokens to agents.  Trusted by the person to issue agent
      tokens only to authorized agents.  Identified by an HTTPS URL
      Section 12.9.1 and publishes metadata at /.well-known/aauth-
      agent.json.
   *  *Resource*: A server that requires authentication and/or
      authorization to protect access to its APIs and data.  A resource
      MAY enforce access policy itself or delegate policy evaluation to
      an access server.  Identified by an HTTPS URL Section 12.9.1 and
      publishes metadata at /.well-known/aauth-resource.json.  A
      mission-aware resource includes the mission object from the AAuth-
      Mission header in the resource tokens it issues.
   *  *Person Server (PS)*: A server that represents the person to the
      rest of the protocol.  The person chooses their PS; it is not
      imposed by any other party.  The PS manages missions, handles
      consent, asserts user identity, and brokers authorization on
      behalf of agents.  Identified by an HTTPS URL Section 12.9.1 and
      publishes metadata at /.well-known/aauth-person.json.
   *  *Access Server (AS)*: A policy engine that evaluates token
      requests, applies resource policy, and issues auth tokens on
      behalf of a resource.  Identified by an HTTPS URL Section 12.9.1
      and publishes metadata at /.well-known/aauth-access.json.
   Tokens:
   *  *Agent Token*: Issued by an agent server to establish the agent&#x27;s
      identity.  MAY declare the agent&#x27;s person server Section 5.2.
   *  *Resource Token*: Issued by a resource to describe the access the
      agent needs Section 6.
   *  *Auth Token*: Issued by a PS or AS to grant an agent access to a
      resource, containing identity claims and/or authorized scopes
      Section 9.4.
   Protocol concepts:
   *  *Mission*: A scoped authorization context for agent governance
      Section 8.  Required when the person&#x27;s PS requires governance over
      the agent&#x27;s actions.  A mission is a JSON object containing
      structured fields (approver, agent, approved_at, approved tools)
      and a Markdown description.  Identified by the PS and SHA-256 hash
      of the mission JSON (s256).  Missions are proposed by agents and
      approved by the PS and person.
   *  *Mission Log*: The ordered record of all agent↔PS interactions
      within a mission — token requests, permission requests, audit
      records, interaction requests, and clarification chats.  The PS
      maintains the log and uses it to evaluate whether each new request
      is consistent with the mission&#x27;s intent Section 8.3.
   *  *HTTP Sig*: An HTTP Message Signature ([RFC9421]) created per the
      AAuth HTTP Message Signatures profile defined in this
      specification Section 12.7, using a key conveyed via the
      Signature-Key header ([I-D.hardt-httpbis-signature-key]).
   *  *Markdown*: AAuth uses Markdown ([CommonMark]) as the human-
      readable content format for mission descriptions, justifications,
      clarifications, and scope descriptions.  Implementations MUST
      sanitize Markdown before rendering to users.
   *  *Interaction*: User authentication, consent, or other action at an
      interaction endpoint Section 7.2.  Triggered when a server returns
      202 Accepted with requirement=interaction.
   *  *Justification*: A Markdown string provided by the agent declaring
      why access is needed, presented to the user by the PS during
      consent Section 7.1.
   *  *Clarification*: A Markdown string containing a question posed to
      the agent by the user during consent via the PS Section 7.3.  The
      agent may respond with an explanation or an updated request.
   4.  Protocol Overview
   All AAuth tokens are JWTs verified using a JWK retrieved from the
   jwks_uri in the issuer&#x27;s well-known metadata, binding each token to
   the server that issued it.
   AAuth has two dimensions: *resource access modes* and *agent
   governance*. Resource access modes define how an agent gets
   authorized at a resource.  Agent governance — missions, permissions,
   audit — is an orthogonal layer that any agent with a person server
   can add, independent of which access mode the resource supports.
   4.1.  Resource Access Modes
   AAuth supports four resource access modes, each adding parties and
   capabilities.  The protocol works in every mode — adoption does not
   require coordination between parties.
     +==================+==========+================================+
     | Mode             | Parties  | Description                    |
     +==================+==========+================================+
     | Identity-based   | Agent    | Resource verifies agent&#x27;s      |
     | access           | Resource | signed identity and applies    |
     |                  |          | its own access control         |
     +------------------+----------+--------------------------------+
     | Resource-managed | Agent    | Resource manages authorization |
     | access           | Resource | with interaction, consent, or  |
     | (two-party)      |          | existing auth infrastructure   |
     +------------------+----------+--------------------------------+
     | PS-managed       | Agent    | Resource issues resource token |
     | access           | Resource | to PS;                         |
     | (three-party)    | PS       | PS issues auth token           |
     +------------------+----------+--------------------------------+
     | Federated access | Agent    | Resource has its own access    |
     | (four-party)     | Resource | server;                        |
     |                  | PS       | PS federates with AS           |
     |                  | AS       |                                |
     +------------------+----------+--------------------------------+
                                 Table 1
   The following diagram shows all parties and their relationships.  Not
   all parties or relationships are present in every mode.
                        +--------------+
                        |    Person    |
                        +--------------+
                         ^           ^
                 mission |           | consent
                         v           v
                        +--------------+    federation    +--------------+
                        |              |-----------------&gt;|              |
                        |   Person     |                  |   Access     |
                        |   Server     |&lt;-----------------|   Server     |
                        |              |    auth token    |              |
                        +--------------+                  +--------------+
                         ^          ^ |
               mission   | resource | | auth
                         |    token | | token
                         |          | v
                 agent  +--------------+  signed request  +--------------+
   +-----------+ token  |              |-----------------&gt;|              |
   |   Agent   |-------&gt;|    Agent     |                  |   Resource   |
   |   Server  |        |              |&lt;-----------------|              |
   +-----------+        +--------------+     resource     +--------------+
                Figure 1: Protocol Parties and Relationships
   *  *Agent Server → Agent*: Issues an agent token binding the agent&#x27;s
      signing key to its identity.
   *  *Agent ↔ Resource*: Agent sends signed requests; resource returns
      responses.  In PS-managed and federated modes, the resource also
      returns resource tokens at its authorization endpoint.
   *  *Agent ↔ PS*: Agent sends resource tokens to obtain auth tokens.
      With governance, agent also creates missions and requests
      permissions.
   *  *PS ↔ AS*: Federation (four-party only).  The PS sends the
      resource token to the AS; the AS returns an auth token.
   *  *Person ↔ PS*: Mission approval and consent for resource access.
   Detailed end-to-end flows are in Appendix B.  The following
   subsections describe each mode.
   4.1.1.  Identity-Based Access
   The agent signs requests with its agent token Section 5.2.  The
   resource verifies the agent&#x27;s identity via HTTP signatures and
   applies its own access control policy — granting or denying based on
   who the agent is.  This replaces API keys with cryptographic
   identity.  No authorization flow, no tokens beyond the agent token.
   Agent                                        Resource
     |                                             |
     | HTTPSig w/ agent token                      |
     |--------------------------------------------&gt;|
     |                                             |
     | 200 OK                                      |
     |&lt;--------------------------------------------|
                      Figure 2: Identity-Based Access
   4.1.2.  Resource-Managed Access (Two-Party)
   The resource handles authorization itself — via interaction
   Section 7.2, existing OAuth/OIDC infrastructure, or internal policy.
   After authorization, the resource MAY return an AAuth-Access header
   Section 6.3 with an opaque access token for subsequent calls.
   Agent                                        Resource
     |                                             |
     | HTTPSig w/ agent token                      |
     |--------------------------------------------&gt;|
     |                                             |
     | 202 (interaction required)                  |
     |&lt;--------------------------------------------|
     |                                             |
     | [user completes interaction]                |
     |                                             |
     | GET pending URL                             |
     |--------------------------------------------&gt;|
     |                                             |
     | 200 OK                                      |
     | AAuth-Access: opaque-token                  |
     |&lt;--------------------------------------------|
     |                                             |
     | HTTPSig w/ agent token                      |
     | Authorization: AAuth opaque-token           |
     |--------------------------------------------&gt;|
     |                                             |
     | 200 OK                                      |
     |&lt;--------------------------------------------|
