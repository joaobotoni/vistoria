package com.botoni.vistoria.data.datasource

import android.util.Log
import android.content.Context
import androidx.credentials.Credential
import androidx.credentials.CustomCredential
import com.google.firebase.auth.FirebaseAuth
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import com.google.firebase.auth.GoogleAuthProvider
import androidx.credentials.ClearCredentialStateRequest
import com.botoni.vistoria.R
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential.Companion.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.tasks.await
import javax.inject.Inject

class GoogleClientRemoteDataSource @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private var isFirstLogin = true
    private val firebaseAuth: FirebaseAuth = FirebaseAuth.getInstance()
    private val credentialManager: CredentialManager = CredentialManager.create(context)
    private val webClientId: String = ""

    companion object {
        private const val TAG = "GoogleAuth"
    }

    suspend fun signInWithGoogle() {
        val response = buildCredentialRequest()
        authenticateWithFirebase(response.credential)
    }

    private suspend fun buildCredentialRequest(): GetCredentialResponse {
        val googleIdOption = createGoogleIdOption()
        val request = createCredentialRequest(googleIdOption)
        return credentialManager.getCredential(request = request, context = context)
    }

    private fun createGoogleIdOption(): GetGoogleIdOption {
        return GetGoogleIdOption.Builder()
            .setServerClientId(webClientId)
            .setFilterByAuthorizedAccounts(!isFirstLogin)
            .setAutoSelectEnabled(!isFirstLogin)
            .build()
    }

    private fun createCredentialRequest(googleIdOption: GetGoogleIdOption): GetCredentialRequest {
        return GetCredentialRequest.Builder()
            .addCredentialOption(googleIdOption)
            .build()
    }

    private suspend fun authenticateWithFirebase(credential: Credential) {
        when {
            isValidGoogleCredential(credential) -> {
                val googleToken = extractGoogleToken(credential)
                signInWithFirebaseCredential(googleToken)
            }
            else -> {
                throw IllegalArgumentException("Invalid credential type received for Google sign-in.")
            }
        }
    }

    private fun isValidGoogleCredential(credential: Credential): Boolean {
        return credential is CustomCredential && credential.type == TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
    }

    private fun extractGoogleToken(credential: Credential): String {
        val googleIdTokenCredential = GoogleIdTokenCredential.createFrom((credential as CustomCredential).data)
        return googleIdTokenCredential.idToken
    }

    private suspend fun signInWithFirebaseCredential(idToken: String) {
        val authCredential = GoogleAuthProvider.getCredential(idToken, null)
        firebaseAuth.signInWithCredential(authCredential).await()
        onLoginSuccess("Successfully signed in with Google")
    }

    suspend fun signOut() {
        clearCredentialState()
        firebaseAuth.signOut()
        onLoginSuccess("User signed out successfully")
    }

    private suspend fun clearCredentialState() {
        credentialManager.clearCredentialState(ClearCredentialStateRequest())
    }

    private fun onLoginSuccess(message: String) {
        isFirstLogin = false
        Log.d(TAG, message)
    }
}