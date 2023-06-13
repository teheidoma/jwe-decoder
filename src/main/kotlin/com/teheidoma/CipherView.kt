package com.teheidoma

import javafx.beans.property.SimpleBooleanProperty
import javafx.beans.property.SimpleStringProperty
import javafx.geometry.Insets
import javafx.scene.control.Alert
import javafx.scene.layout.Priority
import org.jose4j.base64url.Base64
import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import tornadofx.*
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class CipherView: View("cipher view") {
    private val tokenProperty = SimpleStringProperty()
    private val privateKeyProperty = SimpleStringProperty()
    private val publicKeyProperty = SimpleStringProperty()
    private val resultProperty = SimpleStringProperty()
    private val resultBase64Property = SimpleStringProperty()

    private val canDecode = SimpleBooleanProperty()
    private val canEncode = SimpleBooleanProperty()

    override val root = hbox {
        vbox {
            label("Token")
            textarea(tokenProperty) {
                isWrapText = true
                useMaxHeight = true
                vgrow = Priority.ALWAYS
            }
            spacer(Priority.SOMETIMES)
            button("Decode") {
                useMaxWidth = true
                action {
                    decode()
                }
                enableWhen(canDecode)
            }
            hgrow = Priority.ALWAYS
        }

        vbox {
            padding = Insets(0.0, 5.0, 0.0, 5.0)
            label("Private Key")
            textarea(privateKeyProperty) {
                isWrapText = true
            }
            label("Public Key")
            textarea(publicKeyProperty) {
                isWrapText = true
            }
        }
        vbox {
            hgrow = Priority.ALWAYS
            label("Payload")
            textarea(resultProperty) {
                isWrapText = true
                useMaxHeight = true
                vgrow = Priority.ALWAYS
            }
            textfield(resultBase64Property) {
                isEditable = false
                onLeftClick(clickCount = 2) {
                    clipboard.setContent {
                        this.putString(resultBase64Property.get())
                        alert(Alert.AlertType.INFORMATION, header = "Copied to clipboard")
                    }
                }
            }
            button("Encode") {
                useMaxWidth = true
                action {
                    encode()
                }
                enableWhen(canEncode)
            }
        }
    }

    init {
        canDecode.bind(tokenProperty.isNotEmpty.and(privateKeyProperty.isNotEmpty))
        canEncode.bind(resultProperty.isNotEmpty.and(publicKeyProperty.isNotEmpty))

        resultProperty.onChange {
            if (it != null) {
                resultBase64Property.set(Base64.encode(it.toByteArray()))
            }
        }
    }

    private fun encode() {
        val jwe = JsonWebEncryption()
        jwe.payload = resultProperty.get()
        jwe.algorithmHeaderValue = KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW
        jwe.encryptionMethodHeaderParameter = ContentEncryptionAlgorithmIdentifiers.AES_256_GCM
        jwe.key = parsePublicKey()
        tokenProperty.set(jwe.compactSerialization)
    }

    private fun decode() {
        val jwe = JsonWebEncryption()
        jwe.setAlgorithmConstraints(
            AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.PERMIT,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW
            )
        )
        jwe.setContentEncryptionAlgorithmConstraints(
            AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.PERMIT,
                ContentEncryptionAlgorithmIdentifiers.AES_256_GCM
            )
        )
        jwe.key = parsePrivateKey()
        jwe.compactSerialization = tokenProperty.get()

        resultProperty.set(jwe.payload)
    }

    private fun parsePrivateKey(): PrivateKey {
        var pkcs8Pem: String = privateKeyProperty.get()
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "")
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "")
        pkcs8Pem = pkcs8Pem.replace("\\s+".toRegex(), "")

        val keySpec = PKCS8EncodedKeySpec(Base64.decode(pkcs8Pem))
        val factory = KeyFactory.getInstance("EC")

        return factory.generatePrivate(keySpec)
    }

    private fun parsePublicKey(): PublicKey {
        var pkcs8Pem: String = publicKeyProperty.get()
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PUBLIC KEY-----", "")
        pkcs8Pem = pkcs8Pem.replace("-----END PUBLIC KEY-----", "")
        pkcs8Pem = pkcs8Pem.replace("\\s+".toRegex(), "")

        val keySpec = X509EncodedKeySpec(Base64.decode(pkcs8Pem))
        val factory = KeyFactory.getInstance("EC")

        return factory.generatePublic(keySpec)
    }
}
