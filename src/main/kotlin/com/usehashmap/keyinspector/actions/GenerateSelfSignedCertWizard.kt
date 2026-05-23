package com.usehashmap.keyinspector.actions

import com.intellij.openapi.fileChooser.FileChooserDescriptor
import com.intellij.openapi.fileChooser.FileChooserFactory
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import com.usehashmap.keyinspector.service.*
import java.awt.*
import java.io.File
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

/**
 * Multi-step wizard for generating a self-signed X.509 certificate.
 *
 * Steps:
 *  1. Subject & Validity  (CN, O, C, validity days)
 *  2. Key Algorithm       (RSA 2048/4096, EC P-256/P-384)
 *  3. Subject Alt Names   (dynamic list of DNS + IP entries)
 *  4. Output              (format choice + destination path + passwords + alias)
 */
class GenerateSelfSignedCertWizard(project: Project, preselectedKeystore: File? = null)
    : DialogWrapper(project, true) {

    // ─── Step panels ──────────────────────────────────────────────────────────

    private val step1 = Step1SubjectPanel()
    private val step2 = Step2KeyAlgorithmPanel()
    private val step3 = Step3SanPanel()
    private val step4 = Step4OutputPanel(project, preselectedKeystore)

    private val steps: List<WizardStep> = listOf(step1, step2, step3, step4)
    private var currentStep = 0

    // ─── Navigation buttons ───────────────────────────────────────────────────

    private val backButton  = JButton("← Back").apply { isVisible = false }
    private val nextButton  = JButton("Next →")
    private val finishButton = JButton("Finish").apply { isEnabled = false }

    // ─── Container ────────────────────────────────────────────────────────────

    private val stepTitle = JLabel("", SwingConstants.LEFT).apply {
        font = font.deriveFont(Font.BOLD, 14f)
    }
    private val stepHint  = JLabel("", SwingConstants.LEFT).apply {
        font = font.deriveFont(12f)
        foreground = JBColor.GRAY
    }
    private val progressLabel = JLabel("Step 1 of 4", SwingConstants.RIGHT).apply {
        font = font.deriveFont(11f)
        foreground = JBColor.GRAY
    }
    private val cardPanel = JPanel(CardLayout())

    // ─── Init ─────────────────────────────────────────────────────────────────

    init {
        title = "Generate Self-Signed Certificate"
        isModal = true

        steps.forEachIndexed { i, step ->
            cardPanel.add(step.panel(), "step$i")
        }

        backButton.addActionListener  { navigate(-1) }
        nextButton.addActionListener  { navigate(+1) }
        finishButton.addActionListener {
            if (doValidateCurrentStep() == null) close(OK_EXIT_CODE)
        }

        // live validation refresh — re-evaluate Finish button on every keystroke
        steps.forEach { it.addValidationListener { refreshFinishButton() } }

        init()
        showStep(0)
    }

    // ─── Navigation ───────────────────────────────────────────────────────────

    private fun navigate(delta: Int) {
        if (delta > 0 && doValidateCurrentStep() != null) return   // block forward on error
        currentStep = (currentStep + delta).coerceIn(0, steps.lastIndex)
        showStep(currentStep)
    }

    private fun showStep(index: Int) {
        currentStep = index
        (cardPanel.layout as CardLayout).show(cardPanel, "step$index")

        val step = steps[index]
        stepTitle.text     = step.title
        stepHint.text      = step.hint
        progressLabel.text = "Step ${index + 1} of ${steps.size}"

        backButton.isVisible  = index > 0
        nextButton.isVisible  = index < steps.lastIndex
        finishButton.isEnabled = index == steps.lastIndex && validateAllSteps() == null
    }

    private fun refreshFinishButton() {
        finishButton.isEnabled = currentStep == steps.lastIndex && validateAllSteps() == null
    }

    // ─── Validation ───────────────────────────────────────────────────────────

    private fun doValidateCurrentStep(): ValidationInfo? = steps[currentStep].validate()

    private fun validateAllSteps(): ValidationInfo? =
        steps.firstNotNullOfOrNull { it.validate() }

    override fun doValidate(): ValidationInfo? = doValidateCurrentStep()

    override fun doOKAction() {
        val vi = validateAllSteps()
        if (vi != null) { /* shouldn't happen - Finish is gated */ return }
        super.doOKAction()
    }

    // ─── Result accessor ──────────────────────────────────────────────────────

    fun buildParams(): CertGenParams {
        val outputFormat = step4.selectedOutputFormat()
        val outputFile   = step4.outputFile()
        return CertGenParams(
            commonName       = step1.commonName(),
            organization     = step1.organization(),
            country          = step1.country(),
            validityDays     = step1.validityDays(),
            keyAlgorithm     = step2.selectedAlgorithm(),
            sanDnsNames      = step3.dnsNames(),
            sanIpAddresses   = step3.ipAddresses(),
            outputFormat     = outputFormat,
            keystoreFile     = outputFile,
            keystorePassword = step4.keystorePassword(),
            keystoreType     = when (outputFormat) {
                OutputFormatChoice.NEW_JKS    -> "JKS"
                OutputFormatChoice.NEW_PKCS12 -> "PKCS12"
                OutputFormatChoice.ADD_TO_EXISTING -> {
                    val ext = outputFile?.extension?.lowercase() ?: "jks"
                    when (ext) { "p12", "pfx" -> "PKCS12" else -> "JKS" }
                }
                else -> "JKS"
            },
            alias            = step4.alias(),
            keyPassword      = step4.keyPassword()
        )
    }

    // ─── Dialog UI ────────────────────────────────────────────────────────────

    override fun createCenterPanel(): JComponent {
        cardPanel.border = JBUI.Borders.empty(12)

        val headerPanel = JPanel(BorderLayout()).apply {
            border = JBUI.Borders.empty(8, 12, 4, 12)
            add(JPanel(BorderLayout()).apply {
                add(stepTitle, BorderLayout.CENTER)
                add(progressLabel, BorderLayout.EAST)
            }, BorderLayout.NORTH)
            add(stepHint, BorderLayout.SOUTH)
        }

        val north = JPanel(BorderLayout()).apply {
            add(headerPanel, BorderLayout.CENTER)
            add(JSeparator(), BorderLayout.SOUTH)
        }

        return JPanel(BorderLayout()).apply {
            preferredSize = Dimension(600, 480)
            add(north, BorderLayout.NORTH)
            add(cardPanel, BorderLayout.CENTER)
        }
    }

    override fun createSouthPanel(): JComponent {
        return JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4)).apply {
            border = JBUI.Borders.customLine(JBColor.border(), 1, 0, 0, 0)
            add(backButton)
            add(nextButton)
            add(finishButton)
            add(JButton("Cancel").apply { addActionListener { doCancelAction() } })
        }
    }
}

// ─── Wizard step contract ─────────────────────────────────────────────────────

interface WizardStep {
    val title: String
    val hint:  String
    fun panel(): JComponent
    fun validate(): ValidationInfo?
    fun addValidationListener(listener: () -> Unit)
}

// ─── Step 1: Subject & Validity ───────────────────────────────────────────────

private class Step1SubjectPanel : WizardStep {
    override val title = "Subject Information"
    override val hint  = "Enter the distinguished name fields and certificate validity."

    private val cnField = JBTextField().apply { columns = 32 }
    private val orgField = JBTextField().apply { columns = 32 }
    private val countryField = JBTextField().apply {
        columns = 4
        toolTipText = "Two-letter ISO country code, e.g. US"
        document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) { enforceMaxLength() }
            override fun removeUpdate(e: DocumentEvent?) = Unit
            override fun changedUpdate(e: DocumentEvent?) = Unit
            private fun enforceMaxLength() {
                if (text.length > 2) SwingUtilities.invokeLater { text = text.take(2) }
            }
        })
    }
    private val validitySpinner = JSpinner(SpinnerNumberModel(365, 1, 36500, 1)).apply {
        (editor as? JSpinner.DefaultEditor)?.textField?.columns = 6
    }

    private var _panel: JComponent? = null
    private val listeners = mutableListOf<() -> Unit>()

    override fun panel(): JComponent {
        if (_panel != null) return _panel!!
        _panel = FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Common Name (CN):"),      cnField,         true)
            .addLabeledComponent(JBLabel("Organization (O):"),      orgField,        true)
            .addLabeledComponent(JBLabel("Country (C):"),           countryField,    true)
            .addLabeledComponent(JBLabel("Validity (days):"),       validitySpinner, true)
            .addComponentFillVertically(JPanel(), 0)
            .panel.also { it.border = JBUI.Borders.empty(8) }

        val dl = object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = listeners.forEach { it() }
            override fun removeUpdate(e: DocumentEvent?) = listeners.forEach { it() }
            override fun changedUpdate(e: DocumentEvent?) = listeners.forEach { it() }
        }
        cnField.document.addDocumentListener(dl)
        countryField.document.addDocumentListener(dl)
        return _panel!!
    }

    override fun validate(): ValidationInfo? {
        if (cnField.text.isBlank())
            return ValidationInfo("Common Name (CN) must not be empty.", cnField)
        val c = countryField.text.trim()
        if (c.isNotEmpty() && !c.matches(Regex("[A-Za-z]{2}")))
            return ValidationInfo("Country must be exactly 2 letters (ISO 3166-1).", countryField)
        return null
    }

    override fun addValidationListener(listener: () -> Unit) { listeners += listener }

    fun commonName()   = cnField.text.trim()
    fun organization() = orgField.text.trim()
    fun country()      = countryField.text.trim().uppercase()
    fun validityDays() = (validitySpinner.value as Int)
}

// ─── Step 2: Key Algorithm ────────────────────────────────────────────────────

private class Step2KeyAlgorithmPanel : WizardStep {
    override val title = "Key Algorithm"
    override val hint  = "Select the asymmetric key algorithm and size."

    private val choices = KeyAlgorithmChoice.entries.toTypedArray()
    private val buttonGroup = ButtonGroup()
    private val radioButtons = choices.map { choice ->
        JRadioButton(choice.label).also { buttonGroup.add(it) }
    }

    private var _panel: JComponent? = null

    init { radioButtons.first().isSelected = true }

    override fun panel(): JComponent {
        if (_panel != null) return _panel!!
        _panel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = JBUI.Borders.empty(12)
            radioButtons.forEachIndexed { i, rb ->
                rb.alignmentX = Component.LEFT_ALIGNMENT
                add(rb)
                if (i == 1) add(Box.createVerticalStrut(8))  // gap between RSA and EC
            }
            add(Box.createVerticalGlue())
        }
        return _panel!!
    }

    override fun validate(): ValidationInfo? = null  // always has a default selection
    override fun addValidationListener(listener: () -> Unit) = Unit

    fun selectedAlgorithm(): KeyAlgorithmChoice =
        choices[radioButtons.indexOfFirst { it.isSelected }.coerceAtLeast(0)]
}

// ─── Step 3: Subject Alternative Names ───────────────────────────────────────

private class Step3SanPanel : WizardStep {
    override val title = "Subject Alternative Names (SANs)"
    override val hint  = "Add DNS names or IP addresses (optional)."

    private val dnsListModel = DefaultListModel<String>()
    private val ipListModel  = DefaultListModel<String>()
    private val dnsInput  = JBTextField(20)
    private val ipInput   = JBTextField(20)

    private var _panel: JComponent? = null

    override fun panel(): JComponent {
        if (_panel != null) return _panel!!

        val dnsSection = buildSanSection("DNS Names:",  dnsInput,  dnsListModel, "e.g. example.com")
        val ipSection  = buildSanSection("IP Addresses:", ipInput, ipListModel,  "e.g. 192.168.1.1")

        _panel = JPanel(GridLayout(2, 1, 0, 8)).apply {
            border = JBUI.Borders.empty(8)
            add(dnsSection)
            add(ipSection)
        }
        return _panel!!
    }

    private fun buildSanSection(
        labelText: String,
        inputField: JBTextField,
        listModel: DefaultListModel<String>,
        placeholder: String
    ): JPanel {
        inputField.toolTipText = placeholder
        val list     = com.intellij.ui.components.JBList(listModel)
        val addBtn   = JButton("+").apply { preferredSize = Dimension(28, 28) }
        val removeBtn = JButton("−").apply { preferredSize = Dimension(28, 28); isEnabled = false }

        list.addListSelectionListener { removeBtn.isEnabled = !list.isSelectionEmpty }

        addBtn.addActionListener {
            val v = inputField.text.trim()
            if (v.isNotEmpty() && !listModel.contains(v)) {
                listModel.addElement(v)
                inputField.text = ""
            }
        }
        removeBtn.addActionListener {
            list.selectedValuesList.forEach { listModel.removeElement(it) }
        }

        return JPanel(BorderLayout(4, 4)).apply {
            add(JBLabel(labelText), BorderLayout.NORTH)
            add(JScrollPane(list).apply { preferredSize = Dimension(0, 80) }, BorderLayout.CENTER)
            add(JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
                add(inputField)
                add(addBtn)
                add(removeBtn)
            }, BorderLayout.SOUTH)
        }
    }

    override fun validate(): ValidationInfo? = null   // SANs are optional
    override fun addValidationListener(listener: () -> Unit) = Unit

    fun dnsNames():    List<String> = (0 until dnsListModel.size()).map { dnsListModel[it] }
    fun ipAddresses(): List<String> = (0 until ipListModel.size()).map { ipListModel[it] }
}

// ─── Step 4: Output ───────────────────────────────────────────────────────────

private class Step4OutputPanel(private val project: Project, preselectedKeystore: File?) : WizardStep {
    override val title = "Output"
    override val hint  = "Choose where to store the generated certificate and key."

    private val formats = OutputFormatChoice.entries.toTypedArray()
    private val buttonGroup = ButtonGroup()
    private val radioButtons = formats.map { f -> JRadioButton(f.label).also { buttonGroup.add(it) } }

    // Separate text field + browse button so we control the descriptor dynamically
    private val destinationTextField = JBTextField(32)
    private val browseButton = JButton("…").apply { preferredSize = Dimension(30, preferredSize.height) }
    private val destinationField = JPanel(BorderLayout(4, 0)).apply {
        add(destinationTextField, BorderLayout.CENTER)
        add(browseButton, BorderLayout.EAST)
    }
    private val aliasField    = JBTextField(24)
    private val ksPwdField    = JBPasswordField().apply { preferredSize = Dimension(220, preferredSize.height) }
    private val ksPwdConfirm  = JBPasswordField().apply { preferredSize = Dimension(220, preferredSize.height) }
    private val keyPwdField   = JBPasswordField().apply { preferredSize = Dimension(220, preferredSize.height) }
    private val keyPwdConfirm = JBPasswordField().apply { preferredSize = Dimension(220, preferredSize.height) }
    private val showPasswordsCheckBox = createShowPasswordsCheckBox(
        "Show passwords",
        ksPwdField,
        ksPwdConfirm,
        keyPwdField,
        keyPwdConfirm
    )

    private val destLabel  = JBLabel("Destination file:")
    private val aliasLabel = JBLabel("Alias:")
    private val ksPwdLabel = JBLabel("Keystore password:")
    private val ksPwdConfLabel = JBLabel("Confirm keystore password:")
    private val keyPwdLabel = JBLabel("Key password:")
    private val keyPwdConfLabel = JBLabel("Confirm key password:")

    private val listeners = mutableListOf<() -> Unit>()
    private var _panel: JComponent? = null

    init {
        // Default to ADD_TO_EXISTING if a keystore was pre-selected, else NEW_PKCS12
        if (preselectedKeystore != null) {
            radioButtons[0].isSelected = true
            destinationTextField.text  = preselectedKeystore.absolutePath
        } else {
            radioButtons[2].isSelected = true // NEW_PKCS12
        }

        radioButtons.forEach { rb ->
            rb.addActionListener {
                updateBrowseButtonAction()
                updateFieldVisibility()
                listeners.forEach { it() }
            }
        }

        browseButton.addActionListener { doBrowse() }
        updateFieldVisibility()

        val dl = object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = listeners.forEach { it() }
            override fun removeUpdate(e: DocumentEvent?) = listeners.forEach { it() }
            override fun changedUpdate(e: DocumentEvent?) = listeners.forEach { it() }
        }
        aliasField.document.addDocumentListener(dl)
        destinationTextField.document.addDocumentListener(dl)
        ksPwdField.document.addDocumentListener(dl)
        ksPwdConfirm.document.addDocumentListener(dl)
        keyPwdField.document.addDocumentListener(dl)
        keyPwdConfirm.document.addDocumentListener(dl)
    }

    private fun updateBrowseButtonAction() { /* descriptor is read dynamically in doBrowse */ }

    private fun doBrowse() {
        val format = selectedOutputFormat()
        val chooseDirs = format != OutputFormatChoice.ADD_TO_EXISTING
        val descriptor = FileChooserDescriptor(
            !chooseDirs, chooseDirs, false, false, false, false
        ).apply {
            when (format) {
                OutputFormatChoice.ADD_TO_EXISTING -> {
                    withFileFilter { vf -> vf.isDirectory ||
                        vf.extension?.lowercase() in setOf("jks","jceks","bks","p12","pfx","uber","bcfks") }
                    title = "Select Existing Keystore"
                }
                OutputFormatChoice.NEW_JKS    -> { title = "Select Output Directory for JKS" }
                OutputFormatChoice.NEW_PKCS12 -> { title = "Select Output Directory for PKCS#12" }
                OutputFormatChoice.EXPORT_PEM -> { title = "Select Output Directory for PEM Files" }
            }
        }
        val files = FileChooserFactory.getInstance()
            .createFileChooser(descriptor, project, null)
            .choose(project)
        files.firstOrNull()?.let { destinationTextField.text = it.path }
    }

    private fun updateFieldVisibility() {
        val format = selectedOutputFormat()
        val isExisting = format == OutputFormatChoice.ADD_TO_EXISTING
        val isPem      = format == OutputFormatChoice.EXPORT_PEM
        val needsAlias  = !isPem
        val needsKsPwd  = !isPem
        val needsKeyPwd = !isPem

        aliasLabel.isVisible      = needsAlias
        aliasField.isVisible      = needsAlias
        ksPwdLabel.isVisible      = needsKsPwd
        ksPwdField.isVisible      = needsKsPwd
        ksPwdConfLabel.isVisible  = needsKsPwd && !isExisting
        ksPwdConfirm.isVisible    = needsKsPwd && !isExisting
        keyPwdLabel.isVisible     = needsKeyPwd
        keyPwdField.isVisible     = needsKeyPwd
        keyPwdConfLabel.isVisible = needsKeyPwd
        keyPwdConfirm.isVisible   = needsKeyPwd

        destLabel.text = when (format) {
            OutputFormatChoice.ADD_TO_EXISTING -> "Existing keystore:"
            OutputFormatChoice.EXPORT_PEM      -> "Output directory:"
            else                               -> "Output directory:"
        }

        _panel?.revalidate()
        _panel?.repaint()
    }

    override fun panel(): JComponent {
        if (_panel != null) return _panel!!

        _panel = JPanel(BorderLayout(0, 8)).apply {
            border = JBUI.Borders.empty(8)
            add(buildFormatPanel(), BorderLayout.NORTH)
            add(JScrollPane(buildFieldsPanel(), JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER), BorderLayout.CENTER)
        }

        updateFieldVisibility()
        return _panel!!
    }

    private fun buildFormatPanel(): JPanel = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        border = BorderFactory.createTitledBorder("Output Format")
        radioButtons.forEach { rb ->
            rb.alignmentX = Component.LEFT_ALIGNMENT
            add(rb)
        }
    }

    private fun buildFieldsPanel(): JPanel = FormBuilder.createFormBuilder()
        .addLabeledComponent(destLabel,        destinationField, true)
        .addLabeledComponent(aliasLabel,       aliasField,       true)
        .addSeparator()
        .addLabeledComponent(ksPwdLabel,       ksPwdField,       true)
        .addLabeledComponent(ksPwdConfLabel,   ksPwdConfirm,     true)
        .addSeparator()
        .addLabeledComponent(keyPwdLabel,      keyPwdField,      true)
        .addLabeledComponent(keyPwdConfLabel,  keyPwdConfirm,    true)
        .addComponent(showPasswordsCheckBox)
        .addComponentFillVertically(JPanel(), 0)
        .panel

    override fun validate(): ValidationInfo? =
        validateDestination(selectedOutputFormat())
            ?: validateNonPemFields(selectedOutputFormat())

    private fun validateDestination(format: OutputFormatChoice): ValidationInfo? {
        val dest = destinationTextField.text.trim()
        if (dest.isBlank()) {
            return ValidationInfo("Please select a destination.", destinationTextField)
        }

        return when (format) {
            OutputFormatChoice.ADD_TO_EXISTING -> {
                val file = File(dest)
                if (!file.isFile) ValidationInfo("Keystore file does not exist.", destinationTextField) else null
            }

            OutputFormatChoice.NEW_JKS,
            OutputFormatChoice.NEW_PKCS12,
            OutputFormatChoice.EXPORT_PEM -> {
                val directory = File(dest)
                if (!directory.exists() && !directory.mkdirs()) {
                    ValidationInfo("Cannot create output directory.", destinationTextField)
                } else {
                    null
                }
            }
        }
    }

    private fun validateAliasAndPasswords(format: OutputFormatChoice): ValidationInfo? {
        if (aliasField.text.isBlank()) {
            return ValidationInfo("Alias must not be empty.", aliasField)
        }

        if (format != OutputFormatChoice.ADD_TO_EXISTING) {
            val p1 = ksPwdField.password
            val p2 = ksPwdConfirm.password
            if (!p1.contentEquals(p2)) {
                return ValidationInfo("Keystore passwords do not match.", ksPwdConfirm)
            }
        }

        val kp1 = keyPwdField.password
        val kp2 = keyPwdConfirm.password
        return if (!kp1.contentEquals(kp2)) {
            ValidationInfo("Key passwords do not match.", keyPwdConfirm)
        } else {
            null
        }
    }

    private fun validateNonPemFields(format: OutputFormatChoice): ValidationInfo? {
        if (format == OutputFormatChoice.EXPORT_PEM) {
            return null
        }
        return validateAliasAndPasswords(format)
    }

    override fun addValidationListener(listener: () -> Unit) { listeners += listener }

    fun selectedOutputFormat(): OutputFormatChoice =
        formats[radioButtons.indexOfFirst { it.isSelected }.coerceAtLeast(0)]

    fun outputFile(): File? {
        val dest = destinationTextField.text.trim()
        if (dest.isBlank()) return null
        val format = selectedOutputFormat()
        return when (format) {
            OutputFormatChoice.ADD_TO_EXISTING -> File(dest)
            OutputFormatChoice.NEW_JKS -> {
                val safeAlias = aliasField.text.trim().replace(Regex("[^A-Za-z0-9_\\-]"), "_")
                File(dest, "$safeAlias.jks")
            }
            OutputFormatChoice.NEW_PKCS12 -> {
                val safeAlias = aliasField.text.trim().replace(Regex("[^A-Za-z0-9_\\-]"), "_")
                File(dest, "$safeAlias.p12")
            }
            OutputFormatChoice.EXPORT_PEM -> File(dest)
        }
    }

    fun alias()            = aliasField.text.trim()
    fun keystorePassword() = ksPwdField.password
    fun keyPassword()      = keyPwdField.password.takeIf { it.isNotEmpty() } ?: ksPwdField.password
}
