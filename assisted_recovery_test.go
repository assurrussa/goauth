package goauth

import (
 "bytes"
 "testing"
 "time"
)

func TestAssistedRecoverySnapshotRejectsStaleAndMalformedState(t *testing.T) {
 now := time.Date(2026,10,17,0,0,0,0,time.UTC)
 subject, actor := NewSubjectID(),NewSubjectID()
 account := Account{Subject:Subject{ID:subject,Status:SubjectStatusActive,SecurityVersion:7},
  PrimaryEmail:Identifier{NormalizedValue:"old@example.test"}}
 digest := SecretDigest{KeyID:"test",Digest:bytes.Repeat([]byte{2},32)}
 valid := AssistedRecoveryRecord{Selector:"selector",SubjectID:subject,ActorID:actor,Digest:digest,
  SecurityVersion:7,TargetVersion:7,OldEmail:"old@example.test",NewEmail:"new@example.test",
  CreatedAt:now.Add(-time.Minute),ExpiresAt:now.Add(time.Minute)}
 if !validAssistedRecoveryRecord(valid,account,digest,now) { t.Fatal("valid record denied") }
 for _, test := range []struct{name string; mutate func(*AssistedRecoveryRecord)}{
  {"subject",func(r *AssistedRecoveryRecord){r.SubjectID=actor}},
  {"actor",func(r *AssistedRecoveryRecord){r.ActorID=NilSubjectID}},
  {"security version",func(r *AssistedRecoveryRecord){r.SecurityVersion--}},
  {"target version",func(r *AssistedRecoveryRecord){r.TargetVersion=0}},
  {"old email",func(r *AssistedRecoveryRecord){r.OldEmail="other@example.test"}},
  {"same email",func(r *AssistedRecoveryRecord){r.NewEmail=r.OldEmail}},
  {"deadline",func(r *AssistedRecoveryRecord){r.ExpiresAt=now}},
  {"future issue",func(r *AssistedRecoveryRecord){r.CreatedAt=now.Add(time.Second)}},
  {"unbounded lifetime",func(r *AssistedRecoveryRecord){r.ExpiresAt=r.CreatedAt.Add(AssistedRecoveryLifetime+time.Second)}},
  {"key",func(r *AssistedRecoveryRecord){r.Digest.KeyID="other"}},
  {"digest",func(r *AssistedRecoveryRecord){r.Digest=SecretDigest{KeyID:"test",Digest:bytes.Repeat([]byte{3},32)}}},
 } {
  t.Run(test.name,func(t *testing.T){ record:=valid; test.mutate(&record); if validAssistedRecoveryRecord(record,account,digest,now){t.Fatal("invalid record accepted")} })
 }
 account.Subject.Status=SubjectStatusSuspended
 if validAssistedRecoveryRecord(valid,account,digest,now){t.Fatal("inactive account accepted")}
}

func TestAssistedRecoveryRequiresAuditableIndependentVerification(t *testing.T) {
 for _, pair := range [][2]string{{"","reference"},{"reason",""},{"reason\nsecret","reference"},{"reason","reference\x00"}} {
  if validAssistedRecoveryReason(pair[0],pair[1]) { t.Fatal("invalid reason/reference accepted") }
 }
 if !validAssistedRecoveryReason("Lost access to password and prior mailbox","Verified on established support call #42") { t.Fatal("valid attestation denied") }
 if _,err:=NewAssistedRecovery(nil,nil,"https://example.test/recover");err!=ErrAssistedRecoveryUnavailable{t.Fatal(err)}
}
