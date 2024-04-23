package main

import (
	"bytes"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/pluginpb"
	"gopkg.in/yaml.v2"
	"istio.io/tools/pkg/protomodel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admission "k8s.io/kubernetes/pkg/apis/admissionregistration"
)

const (
	enableCRDGenTag = "+cue-gen"
)

var (
	istioAPIGroups = []string{
		"networking.istio.io",
		"security.istio.io",
		"telemetry.istio.io",
		"extensions.istio.io",
	}

	specialIterableTypes = map[string]struct{}{
		"google.protobuf.ListValue": {},
	}
)

type fieldType string

var (
	fieldTypePrimitive fieldType = "primitive"
	fieldTypeMap       fieldType = "map"
	fieldTypeList      fieldType = "list"
)

type fieldKey struct {
	name      string
	fieldType bool
}

type celGenerator struct {
	model    *protomodel.Model
	messages map[string]*protomodel.MessageDescriptor
	// transient state as individual files are processed
	currentPackage       *protomodel.PackageDescriptor
	currentFieldPathTree map[fieldKey]any // the value type here is really a nested map of fieldKeys
}

func newCelGenerator(model *protomodel.Model) *celGenerator {
	return &celGenerator{
		model: model,
	}
}

// GenerateValidation generates a ValidatingAdmissionPolicy
// that blocks the usage of fields and CRDs that are in the extended channel.
func (g *celGenerator) GenerateValidationPolicy(
	filesToGen map[*protomodel.FileDescriptor]bool,
	fileName string,
) pluginpb.CodeGeneratorResponse_File {
	messages := make(map[string]*protomodel.MessageDescriptor)
	enums := make(map[string]*protomodel.EnumDescriptor)
	descriptions := make(map[string]string)

	for file, ok := range filesToGen {
		if ok {
			g.getFileContents(file, messages, enums, descriptions)
		}
	}

	return g.generateFile(fileName, messages, enums, descriptions)
}

// Generate an OpenAPI spec for a collection of cross-linked files.
func (g *celGenerator) generateFile(
	name string,
	messages map[string]*protomodel.MessageDescriptor,
	enums map[string]*protomodel.EnumDescriptor,
	descriptions map[string]string,
) pluginpb.CodeGeneratorResponse_File {
	g.messages = messages

	// Key -> Validation
	validations := map[string]admission.Validation{}
	// Type --> Key --> Value
	messageGenTags := map[string]map[string]string{}

	for _, message := range messages {
		// we validations based on top-level messages here; nested fields are handled
		// as we process the root messages
		if message.Parent == nil {
			g.generateValidations(message)
		}
		if gt := parseMessageGenTags(message.Location().GetLeadingComments()); gt != nil {
			messageGenTags[g.absoluteName(message)] = gt
		}
	}

	for name, cfg := range messageGenTags {
		// We don't care about versions; one VAP is enough for all versions
		if _, f := validations[name]; f {
			continue
		}
		if cfg["releaseChannel"] != "extended" {
			log.Printf("Skipping validation for stable resource %s", name)
			continue
		}
		// Never allow this resource to be created/updated (only deleted)
		log.Println("Generating", name)
		celValidation := fmt.Sprintf(`
			object.kind == %s
		`, name)

		validation := admission.Validation{
			Expression: celValidation,
		}

		validations[name] = validation
	}

	// sort the configs so that the order is deterministic.
	keys := maps.Keys(validations)
	slices.SortFunc(keys, func(a, b string) int {
		if a < b {
			return -1
		}
		return 1
	})

	bb := &bytes.Buffer{}
	vap := &admission.ValidatingAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1beta1",
			Kind:       "ValidatingAdmissionPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "stable-channel.istio.io",
		},
		Spec: admission.ValidatingAdmissionPolicySpec{
			FailurePolicy: Ptr(admission.Fail),
			MatchConstraints: &admission.MatchResources{
				ResourceRules: []admission.NamedRuleWithOperations{
					{
						RuleWithOperations: admission.RuleWithOperations{
							// Deletes should be allowed to clean up potentially broken state
							Operations: []admission.OperationType{admission.Create, admission.Update},
							Rule: admission.Rule{
								APIGroups:   istioAPIGroups,
								APIVersions: []string{"*"},
								Resources:   []string{"*"},
							},
						},
					},
				},
			},
		},
	}
	bb.WriteString("# DO NOT EDIT - Generated based on Istio APIs.\n")
	for _, name := range keys {
		validation := validations[name]
		vap.Spec.Validations = append(vap.Spec.Validations, validation)
	}

	b, err := yaml.Marshal(vap)
	if err != nil {
		log.Fatalf("unable to marshall the output of %v to yaml", vap.Name)
	}
	b = fixupYaml(b)
	bb.Write(b)

	return pluginpb.CodeGeneratorResponse_File{
		Name:    proto.String(stableAdmissionPolicyName),
		Content: proto.String(bb.String()),
	}
}

func (g *celGenerator) fieldValidations(path string, field *protomodel.FieldDescriptor) []string {
	var validations []string

	messageType := descriptor.FieldDescriptorProto_TYPE_MESSAGE
	enumType := descriptor.FieldDescriptorProto_TYPE_ENUM
	gt := parseMessageGenTags(field.Location().GetLeadingComments())
	// If this is an extended field, add a validation for it and don't do any more work
	if gt != nil && gt["releaseChannel"] == "extended" {
		validation := fmt.Sprintf("has(object.spec.%s.%s)", path, field)
		if len(path) == 0 {
			validation = fmt.Sprintf("has(object.spec.%s)", field)
		}
		validations = append(validations, validation)
		return validations
	}

	// If this isn't an extended field, we need to dig deeper into its subfields (if it has any)
	var isIterable bool
	switch *field.Type {
	case enumType:
		enum := field.FieldType.(*protomodel.EnumDescriptor)
		// Check if there's an enum value set in the extended channel
		var extendedValues []string
		for _, v := range enum.Values {
			enumGenTags := parseMessageGenTags(v.Location().GetLeadingComments())
			if enumGenTags != nil && enumGenTags["releaseChannel"] == "extended" {
				extendedValues = append(extendedValues, *v.Name)
			}
		}
		validation := fmt.Sprintf("object.spec.%s.%s in [%s]", path, field, strings.Join(extendedValues, ", "))
		if len(path) == 0 {
			validation = fmt.Sprintf("object.spec.%s in [%s]", field, strings.Join(extendedValues, ", "))
		}
	case messageType:
		msg := field.FieldType.(*protomodel.MessageDescriptor)
		_, ok := specialIterableTypes[g.absoluteName(msg)]
		// Iterable fields need a .all macro in the CEL expression
		if ok || field.IsRepeated() {
			isIterable = true
		}
		if msg.GetOptions().GetMapEntry() {
			// Maps need to be handled a little differently; if the value type is an enum or a message
			// we need to account for an extended value that may be set in the value of a map entry
			isIterable = true
			mapValue := msg.Fields[1]
			if mapValue.GetType() == enumType {
				// Does there exist a key whose value is set to an enum in the extended channel?
				validation := `object.spec.portLevelMtls.exists(key, object.spec.portLevelMtls[key] == "DISABLED")`

			}
		} else if isIterable {

		} else {
			gt := parseMessageGenTags(field.Location().GetLeadingComments())
			if gt == nil {
				return nil
			}
			if gt["releaseChannel"] != "extended" {
				return nil
			}
			validations = append(validations, g.generateValidations(msg)...)
		}
	default:
		// If this is a flat field (non-iterable), there's nothing to do here
		return nil
	}

}

func (g *celGenerator) generateValidations(message *protomodel.MessageDescriptor) []string {
	var validations []string
	for _, field := range message.Fields {
		gt := parseMessageGenTags(field.Location().GetLeadingComments())
		validations = append(validations, g.fieldValidations("", field)...)
	}

	return validations
}

func cleanComments(lines []string) []string {
	out := []string{}
	var prevLine string
	for _, line := range lines {
		line = strings.Trim(line, " ")

		if line == "-->" {
			out = append(out, prevLine)
			prevLine = ""
			continue
		}

		if !strings.HasPrefix(line, enableCRDGenTag) {
			if prevLine != "" && len(line) != 0 {
				prevLine += " " + line
			}
			continue
		}

		out = append(out, prevLine)

		prevLine = line

	}
	if prevLine != "" {
		out = append(out, prevLine)
	}
	return out
}

const (
	statusOutput = `
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: null
  storedVersions: null`

	creationTimestampOutput = `
  creationTimestamp: null`
)

func (g *celGenerator) fieldName(field *protomodel.FieldDescriptor) string {
	return field.GetJsonName()
}

func fixupYaml(y []byte) []byte {
	// remove the status and creationTimestamp fields from the output. Ideally we could use OrderedMap to remove those.
	y = bytes.ReplaceAll(y, []byte(statusOutput), []byte(""))
	y = bytes.ReplaceAll(y, []byte(creationTimestampOutput), []byte(""))
	// keep the quotes in the output which is required by helm.
	y = bytes.ReplaceAll(y, []byte("helm.sh/resource-policy: keep"), []byte(`"helm.sh/resource-policy": keep`))
	return y
}

func parseMessageGenTags(s string) map[string]string {
	lines := cleanComments(strings.Split(s, "\n"))
	res := map[string]string{}
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		// +cue-gen:AuthorizationPolicy:groupName:security.istio.io turns into
		// :AuthorizationPolicy:groupName:security.istio.io
		_, contents, f := strings.Cut(line, enableCRDGenTag)
		if !f {
			continue
		}
		// :AuthorizationPolicy:groupName:security.istio.io turns into
		// ["AuthorizationPolicy", "groupName", "security.istio.io"]
		spl := strings.SplitN(contents[1:], ":", 3)
		if len(spl) < 2 {
			log.Fatalf("invalid message tag: %v", line)
		}
		val := ""
		if len(spl) > 2 {
			// val is "security.istio.io"
			val = spl[2]
		}
		if _, f := res[spl[1]]; f {
			// res["groupName"] is "security.istio.io;;newVal"
			res[spl[1]] += ";;" + val
		} else {
			// res["groupName"] is "security.istio.io"
			res[spl[1]] = val
		}
	}
	if len(res) == 0 {
		return nil
	}
	return res
}

func (g *celGenerator) getFileContents(
	file *protomodel.FileDescriptor,
	messages map[string]*protomodel.MessageDescriptor,
	enums map[string]*protomodel.EnumDescriptor,
	descriptions map[string]string,
) {
	for _, m := range file.AllMessages {
		messages[g.relativeName(m)] = m
	}

	for _, e := range file.AllEnums {
		enums[g.relativeName(e)] = e
	}
}

func (g *celGenerator) absoluteName(desc protomodel.CoreDesc) string {
	typeName := protomodel.DottedName(desc)
	return desc.PackageDesc().Name + "." + typeName
}

func (g *celGenerator) relativeName(desc protomodel.CoreDesc) string {
	typeName := protomodel.DottedName(desc)
	if desc.PackageDesc() == g.currentPackage {
		return typeName
	}

	return desc.PackageDesc().Name + "." + typeName
}

func Ptr[T any](t T) *T {
	return &t
}
