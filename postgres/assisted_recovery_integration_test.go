//go:build integration

package postgres_test

import (
 "context"
 "net/url"
 "sync"
 "testing"

 "github.com/assurrussa/goauth"
 "github.com/assurrussa/goauth/postgres"
 "github.com/assurrussa/goauth/testkit"
 "github.com/stretchr/testify/require"
)

type assistedRecoveryPermission struct { denied bool }
func (p assistedRecoveryPermission) AuthorizeAssistedRecovery(context.Context,goauth.AuthContext,goauth.SubjectID,string,string) error {
 if p.denied { return goauth.ErrAssistedRecoveryDenied }; return nil
}

func TestAssistedRecoveryRequiresExistingMFAAndPreservesEnrollment(t *testing.T) {
 f:=newMFAIntegrationFixture(t)
 f.config.NotificationDelivery=goauth.NotificationDeliveryRequired
 var err error
 f.runtime,err=postgres.NewRuntime(postgres.Config{DB:f.db,Runtime:f.config,NotificationSender:integrationNotificationSender()})
 require.NoError(t,err)
 _,codes:=f.enroll(t)
 actor,err:=f.runtime.ProvisionTrustedLocalAccount(t.Context(),goauth.RegisterRequest{Email:"mfa.recovery.operator@example.test",Password:mfaIntegrationPassword})
 require.NoError(t,err)
 logged,err:=f.runtime.Login(t.Context(),goauth.LoginRequest{Realm:goauth.RealmAdmin,Credential:goauth.Credential{Identifier:goauth.IdentifierInput{Scheme:goauth.IdentifierSchemeEmail,Value:actor.PrimaryEmail.NormalizedValue},Password:mfaIntegrationPassword}})
 require.NoError(t,err)
 auth,err:=f.runtime.VerifyAccessToken(t.Context(),logged.Tokens.AccessToken,true);require.NoError(t,err)
 service,err:=goauth.NewAssistedRecovery(f.runtime.Runtime,assistedRecoveryPermission{},"https://app.example.test/auth/assisted-recovery");require.NoError(t,err)
 require.NoError(t,service.Initiate(t.Context(),goauth.AssistedRecoveryRequest{Auth:auth,SubjectID:f.account.Subject.ID,NewEmail:"mfa.restored@example.test",Password:mfaIntegrationPassword,Reason:"Lost mailbox and password",EvidenceReference:"Known channel verified"}))
 observer:=&integrationEventObserver{t:t,db:f.db}
 var token string
 for _,event:=range observer.Events(){if event.Type=="assisted_recovery"{notice,e:=testkit.DecryptNotification(f.config.OutboxAEADKeys,event.Envelope);require.NoError(t,e);link,e:=url.Parse(notice.Data["url"]);require.NoError(t,e);p,e:=url.ParseQuery(link.Fragment);require.NoError(t,e);token=p.Get("token")}}
 require.NotEmpty(t,token)
 completion:=goauth.AssistedRecoveryCompletion{Token:token,NewPassword:"Recovered-MFA-Passphrase-42",Code:"incorrect-factor"}
 require.ErrorIs(t,service.Complete(t.Context(),completion),goauth.ErrAssistedRecoveryDenied)
 var attempts int
 require.NoError(t,f.db.QueryRowContext(t.Context(),`SELECT attempts FROM auth_mfa_budget WHERE subject_id=$1`,f.account.Subject.ID).Scan(&attempts));require.Positive(t,attempts)
 config:=f.config;config.MFAKeys=nil
 missing,err:=postgres.NewRuntime(postgres.Config{DB:f.db,Runtime:config,NotificationSender:integrationNotificationSender()});require.NoError(t,err)
 missingService,err:=goauth.NewAssistedRecovery(missing.Runtime,assistedRecoveryPermission{},"https://app.example.test/auth/assisted-recovery");require.NoError(t,err)
 completion.Code=codes[0]
 require.ErrorIs(t,missingService.Complete(t.Context(),completion),goauth.ErrMFAUnavailable)
 require.NoError(t,service.Complete(t.Context(),completion))
 var enabled bool
 require.NoError(t,f.db.QueryRowContext(t.Context(),`SELECT enabled FROM auth_mfa_factors WHERE subject_id=$1`,f.account.Subject.ID).Scan(&enabled));require.True(t,enabled)
 var remaining int
 require.NoError(t,f.db.QueryRowContext(t.Context(),`SELECT count(*) FROM auth_mfa_recovery WHERE subject_id=$1`,f.account.Subject.ID).Scan(&remaining));require.Equal(t,9,remaining)
 require.Error(t,service.Complete(t.Context(),completion))
}

func TestAssistedRecoveryChangesBothCredentialsOnceAndRevokesPriorAuthority(t *testing.T) {
 db := integrationDB(t)
 runtime, events, keys := integrationRuntime(t,db)
 const original = "Assisted-Recovery-Original-Passphrase-42"
 const replacement = "Assisted-Recovery-Replacement-Passphrase-52"
 actor,err:=runtime.ProvisionTrustedLocalAccount(t.Context(),goauth.RegisterRequest{Email:"operator.recovery@example.test",Password:original})
 require.NoError(t,err)
 target,err:=runtime.ProvisionTrustedLocalAccount(t.Context(),goauth.RegisterRequest{Email:"lost.recovery@example.test",Password:original})
 require.NoError(t,err)
 operator,err:=runtime.Login(t.Context(),goauth.LoginRequest{Credential:goauth.Credential{Identifier:goauth.IdentifierInput{Scheme:goauth.IdentifierSchemeEmail,Value:actor.PrimaryEmail.NormalizedValue},Password:original},Realm:goauth.RealmAdmin})
 require.NoError(t,err)
 auth,err:=runtime.VerifyAccessToken(t.Context(),operator.Tokens.AccessToken,true)
 require.NoError(t,err)
 beforeLogin,err:=runtime.Login(t.Context(),login(target.PrimaryEmail.NormalizedValue,original))
 require.NoError(t,err)
 require.NoError(t,runtime.RequestPasswordReset(t.Context(),target.PrimaryEmail.NormalizedValue))
 require.NoError(t,runtime.RequestEmailChange(t.Context(),target.Subject.ID,"uncompleted.recovery@example.test"))
 service,err:=goauth.NewAssistedRecovery(runtime.Runtime,assistedRecoveryPermission{},"https://app.example.test/auth/assisted-recovery")
 require.NoError(t,err)
 request:=goauth.AssistedRecoveryRequest{Auth:auth,SubjectID:target.Subject.ID,NewEmail:"restored.recovery@example.test",Password:original,
  Reason:"Lost password and old mailbox",EvidenceReference:"Known support channel case 42"}
 bad:=request;bad.Password="incorrect-password"
 require.ErrorIs(t,service.Initiate(t.Context(),bad),goauth.ErrCurrentPasswordInvalid)
 denied,err:=goauth.NewAssistedRecovery(runtime.Runtime,assistedRecoveryPermission{denied:true},"https://app.example.test/auth/assisted-recovery")
 require.NoError(t,err)
 require.ErrorIs(t,denied.Initiate(t.Context(),request),goauth.ErrAssistedRecoveryDenied)
 require.NoError(t,service.Initiate(t.Context(),request))
 unchanged,err:=runtime.GetAccount(t.Context(),target.Subject.ID)
 require.NoError(t,err)
 require.Equal(t,target,unchanged)
 var rawToken string
 for _,event:=range events.Events(){
  if event.Type!="assisted_recovery"{continue}
  notice,e:=testkit.DecryptNotification(keys,event.Envelope);require.NoError(t,e)
  require.Equal(t,request.NewEmail,notice.To)
  link,e:=url.Parse(notice.Data["url"]);require.NoError(t,e)
  fragment,e:=url.ParseQuery(link.Fragment);require.NoError(t,e)
  rawToken=fragment.Get("token");require.Empty(t,link.RawQuery)
 }
 require.NotEmpty(t,rawToken)
 var digest []byte
 require.NoError(t,db.QueryRowContext(t.Context(),`SELECT secret_digest FROM auth_assisted_recovery WHERE subject_id=$1`,target.Subject.ID).Scan(&digest))
 require.Len(t,digest,32)
 require.NotEqual(t,rawToken,string(digest))
 results:=make(chan error,2);var wait sync.WaitGroup
 for range 2 { wait.Add(1);go func(){defer wait.Done();results<-service.Complete(t.Context(),goauth.AssistedRecoveryCompletion{Token:rawToken,NewPassword:replacement})}() }
 wait.Wait();close(results);successes:=0
 for err:=range results {if err==nil{successes++}else{require.Error(t,err)}}
 require.Equal(t,1,successes)
 changed,err:=runtime.GetAccount(t.Context(),target.Subject.ID)
 require.NoError(t,err)
 require.Equal(t,target.Subject.ID,changed.Subject.ID)
 require.Equal(t,target.Subject.SecurityVersion+1,changed.Subject.SecurityVersion)
 require.Equal(t,request.NewEmail,changed.PrimaryEmail.NormalizedValue)
 require.True(t,changed.EmailVerified())
 assertTrustedPasswordInvalidated(t,db,target.Subject.ID)
 _,err=runtime.Refresh(t.Context(),beforeLogin.Tokens.RefreshToken);require.Error(t,err)
 _,err=runtime.Login(t.Context(),login(request.NewEmail,replacement));require.NoError(t,err)
 _,err=runtime.Login(t.Context(),login(target.PrimaryEmail.NormalizedValue,original));require.Error(t,err)
 oldNotice:=false
 for _,event:=range events.Events(){if event.Type=="assisted_recovery_completed"{notice,e:=testkit.DecryptNotification(keys,event.Envelope);require.NoError(t,e);require.Equal(t,target.PrimaryEmail.NormalizedValue,notice.To);oldNotice=true}}
 require.True(t,oldNotice)
}
