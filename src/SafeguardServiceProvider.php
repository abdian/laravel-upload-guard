<?php

namespace Abdian\UploadGuard;

use Abdian\UploadGuard\Rules\SafeguardMime;
use Abdian\UploadGuard\Rules\SafeguardPhp;
use Abdian\UploadGuard\Rules\SafeguardSvg;
use Abdian\UploadGuard\Rules\SafeguardImage;
use Abdian\UploadGuard\Rules\SafeguardPdf;
use Abdian\UploadGuard\Rules\SafeguardDimensions;
use Abdian\UploadGuard\Rules\SafeguardPages;
use Abdian\UploadGuard\Rules\SafeguardArchive;
use Abdian\UploadGuard\Rules\SafeguardOffice;
use Abdian\UploadGuard\Rules\Safeguard;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;

/**
 * SafeguardServiceProvider - Main service provider for Laravel Safeguard package
 *
 * This provider registers all validation rules and publishes configuration files
 */
class SafeguardServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Merge package config with application config
        $this->mergeConfigFrom(
            __DIR__ . '/config/safeguard.php',
            'safeguard'
        );
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        // Publish configuration file
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/config/safeguard.php' => config_path('safeguard.php'),
            ], 'safeguard-config');
        }

        // Register custom validation rules
        $this->registerValidationRules();
    }

    /**
     * Register custom validation rules with Laravel's validator
     *
     * @return void
     */
    protected function registerValidationRules(): void
    {
        // Register safeguard_mime validation rule
        Validator::extend('safeguard_mime', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardMime($parameters);
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_mime', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_mime', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_php validation rule
        Validator::extend('safeguard_php', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardPhp();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_php', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_php', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_svg validation rule
        Validator::extend('safeguard_svg', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardSvg();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_svg', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_svg', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_image validation rule
        Validator::extend('safeguard_image', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardImage();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_image', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_image', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_pdf validation rule
        Validator::extend('safeguard_pdf', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardPdf();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_pdf', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_pdf', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_dimensions validation rule
        Validator::extend('safeguard_dimensions', function ($attribute, $value, $parameters, $validator) {
            // Parse parameters: max_width, max_height, min_width (optional), min_height (optional)
            $maxWidth = isset($parameters[0]) ? (int) $parameters[0] : null;
            $maxHeight = isset($parameters[1]) ? (int) $parameters[1] : null;
            $minWidth = isset($parameters[2]) ? (int) $parameters[2] : null;
            $minHeight = isset($parameters[3]) ? (int) $parameters[3] : null;

            $rule = new SafeguardDimensions($maxWidth, $maxHeight, $minWidth, $minHeight);
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_dimensions', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_dimensions', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_pages validation rule
        Validator::extend('safeguard_pages', function ($attribute, $value, $parameters, $validator) {
            // Parse parameters: min_pages (optional), max_pages (optional)
            $minPages = isset($parameters[0]) ? (int) $parameters[0] : null;
            $maxPages = isset($parameters[1]) ? (int) $parameters[1] : null;

            $rule = new SafeguardPages($minPages, $maxPages);
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_pages', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_pages', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_archive validation rule
        Validator::extend('safeguard_archive', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardArchive($parameters);
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_archive', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_archive', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_office validation rule
        Validator::extend('safeguard_office', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardOffice($parameters);
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_office', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_office', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard validation rule (comprehensive security check)
        // This rule automatically integrates with Laravel's native 'mimes' rule
        Validator::extend('safeguard', function ($attribute, $value, $parameters, $validator) {
            $rule = new Safeguard();

            // Check if 'mimes' rule exists for this attribute and extract allowed extensions
            $allowedMimes = $this->extractMimesFromValidator($validator, $attribute);

            if (!empty($allowedMimes)) {
                $rule->allowedMimes($allowedMimes);

                // Enable strict extension-MIME matching
                $rule->strictExtensionMatching(true);
            }

            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });
    }

    /**
     * Extract MIME types from Laravel's 'mimes' rule if present
     *
     * This method inspects the validator's rules for the given attribute,
     * finds any 'mimes' rule, and converts the extensions to full MIME types.
     *
     * @param \Illuminate\Validation\Validator $validator The validator instance
     * @param string $attribute The attribute name being validated
     * @return array<string> Array of MIME types, empty if no 'mimes' rule found
     */
    protected function extractMimesFromValidator($validator, string $attribute): array
    {
        $rules = $validator->getRules();

        // Handle array attributes (e.g., 'attachments.*' -> check 'attachments.0')
        $baseAttribute = $attribute;
        if (preg_match('/^(.+)\.\d+$/', $attribute, $matches)) {
            $baseAttribute = $matches[1] . '.*';
        }

        // Check both the exact attribute and the wildcard version
        $attributesToCheck = [$attribute, $baseAttribute];

        foreach ($attributesToCheck as $attr) {
            if (!isset($rules[$attr])) {
                continue;
            }

            foreach ($rules[$attr] as $rule) {
                // Handle string rules
                if (is_string($rule)) {
                    if (str_starts_with($rule, 'mimes:')) {
                        $extensions = explode(',', substr($rule, 6));
                        return ExtensionMimeMap::extensionsToMimeTypes($extensions);
                    }
                    if (str_starts_with($rule, 'mimetypes:')) {
                        // If mimetypes is used, extract directly
                        return explode(',', substr($rule, 10));
                    }
                }

                // Handle array rules like ['mimes' => 'jpg,png']
                if (is_array($rule)) {
                    if (isset($rule['mimes'])) {
                        $extensions = is_array($rule['mimes'])
                            ? $rule['mimes']
                            : explode(',', $rule['mimes']);
                        return ExtensionMimeMap::extensionsToMimeTypes($extensions);
                    }
                    if (isset($rule['mimetypes'])) {
                        return is_array($rule['mimetypes'])
                            ? $rule['mimetypes']
                            : explode(',', $rule['mimetypes']);
                    }
                }
            }
        }

        return [];
    }
}
