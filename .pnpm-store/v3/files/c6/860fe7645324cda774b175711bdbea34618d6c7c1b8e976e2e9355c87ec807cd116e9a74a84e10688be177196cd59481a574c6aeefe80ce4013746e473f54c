import { useFormikContext } from 'formik';

export { useField } from 'formik';

export function useSubmit() {
	const { submitForm, isSubmitting } = useFormikContext();

	return [submitForm, isSubmitting] as const;
}

export function useValues() {
	const { values } = useFormikContext();

	return values;
}
